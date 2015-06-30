#!/usr/bin/env pypy

import angr
import sys
import multiprocessing
import argparse
import termcolor
import os
import tempfile
import subprocess
import simuvex
import time
import struct
import archinfo
from simuvex.s_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength
from IPython import embed

binary_start_code = None
binary_end_code = None

outputdir = None
inputdir = None
binary = None

fuzz_bitmap = None
map_size = None

sync_id = None
fuzzer_driller_dir = None

shared_trace_cnt = multiprocessing.Value('L', 0, lock=multiprocessing.Lock())
total_traces = 0

def ok(s):
    status = termcolor.colored("[*]", "cyan", attrs=["bold"])
    print "%s %s" % (status, s)

def success(s):
    status = termcolor.colored("[+]", "green", attrs=["bold"])
    print "%s %s" % (status, s)

def alert(s):
    status = termcolor.colored("[!]", "yellow", attrs=["bold"])
    print "%s %s" % (status, s)

def warning(s):
    status = termcolor.colored("[-]", "red", attrs=["bold"])
    print "%s %s" % (status, s)

def die(s):
    warning(s)
    sys.exit(1)


encountered = {}
found = {}
qemu_traces = {}

# set of input files which have been traced in previous runs
traced = set()

# set of inputs which have already been generated
# we maintain this list to avoid overwhelming AFL with redundant testcases after a driller run
# as far as I know this shouldn't be necessary and two different calls to dump_to_file should
# only be called on either different state transitions or when different data affects an already 
# solved state transition
generated = set()

def dump_to_file(indicies, content, prev, path):
    '''
    :param indices: a list of integers which contain new data which trigger the state transition
    :param content: the content of the input file which missed the state transition
    :param prev: an integer address of the basic block before path
    :param path: a path object which is the destination of the new state transition
    :return: the name of the output file generated as a string
    '''
    abspath = os.path.abspath(outputdir)
    pref = os.path.join(abspath, "driller-%x-%x-" % (prev, path.addr))

    try:
        gen = path.state.posix.dumps(0)
    except simuvex.s_errors.SimFileError: # sometimes we don't even have symbolic data yet
        return ""


    out = gen
    '''
    for index in indicies:
        out = out[:index] + gen[index] + out[index+1:]
    '''

    if out in generated:
        return ""

    generated.add(out)

    fd, outfile = tempfile.mkstemp(prefix=pref)
    os.close(fd) # close the fd, mkstemp returns an open one annoyingly

    fp = open(outfile, "w")
    fp.write(out)
    fp.close()

    # TODO: fix this race condition
    cnt = 0
    try:
        dstats = open("%s/.driller_stats" % fuzzer_driller_dir)
        cnt = int(dstats.read())
        dstats.close()
    except IOError:
        pass

    basename = os.path.basename(outfile)
    # also write the file to the the special output directory
    fp = open("%s/id:%06u,orig:%s" % (fuzzer_driller_dir, cnt, basename), "w")
    fp.write(out)
    fp.close

    dstats = open("%s/.driller_stats" % fuzzer_driller_dir, "w")
    dstats.write(str(cnt + 1))
    dstats.close()

    return outfile

def detect_arch(loader):
    '''
    :param loader: a CLE loader object to extract the architecture from
    :return: a string representing the architecture of the CLE loader instance
    '''

    larch = loader.main_bin.arch
    ltype = loader.main_bin.filetype

    if ltype == "cgc":
        arch = "cgc" 

    if ltype == "elf":
        if larch == archinfo.arch_amd64.ArchAMD64:
            arch = "x86_64"
        if larch == archinfo.arch_x86.ArchX86:
            arch = "i386"

    return arch

def generate_qemu_trace(basedirectory, binary, arch, inputfile):
    '''
    :param basedirectory: base directory of the driller install for locating qemu
    :param binary: the relative path to the binary
    :param arch: the string representation of the architecture of the binary
    :param inputfile: file containing the input to feed to the binary
    :return: a list of basic blocks that qemu encountered while executing
    '''

    qemu_path = os.path.join(basedirectory, "../driller_qemu", "driller-qemu-%s" % arch)
    _, logfile = tempfile.mkstemp(prefix="/dev/shm/driller-trace-")

    # launch qemu asking it to trace the binary for us
    args = [qemu_path, "-D", logfile, "-d", "exec", binary]

    # feed it input
    fp = open(inputfile)
    dp = open("/dev/null", "w")

    # execute the process waiting for it to terminate
    p = subprocess.Popen(args, stdin=fp, stdout=dp)
    p.wait()

    fp.close()
    dp.close()

    # read in the trace and remove the logfile
    trace = open(logfile).read()
    os.remove(logfile)

    # parse the logfile to return a list of addresses
    tracelines = trace.split("\n")
    tracelines = filter(lambda v: v.startswith("Trace"), tracelines)
    tracelines = map(lambda v: int(v.split("[")[1].split("]")[0], 16), tracelines)

    return tracelines

def accumulate_traces(basedirectory, binary_path, loader, inputs):
    global qemu_traces

    alert("accumulating traces for all %d inputs" % len(inputs))

    arch = detect_arch(loader)  

    for inputfile in inputs:
        traces = generate_qemu_trace(basedirectory, binary_path, arch, inputfile) 
        qemu_traces[inputfile] = traces

        # let's just populate encountered now
        for trace in traces:
            if trace not in encountered:
                encountered[trace] = inputfile


def create_and_populate_traced(outputdir):
    global traced

    # make the subdirectory for storing what has already been traced
    trace_file = os.path.join(outputdir, ".traced")
    try:
        traced_inputs = open(trace_file).read()
    except IOError:
        return

    # populate traced
    traced = set(traced_inputs.split("\n"))

def print_trace_stats(bb_cnt, fn, foundsomething):
    trace_cnt_v = shared_trace_cnt.value
    
    p = termcolor.colored("[*]", "cyan", attrs=["bold"])
    excitement = ""
    if foundsomething:
        if foundsomething == 2:
            excitement = termcolor.colored("!", "green", attrs=["bold"])
        if foundsomething == 1:
            excitement = termcolor.colored("!", "red", attrs=["bold"])

    print "%s trace %02d/%d, %d bbs, %s %s" % (p, trace_cnt_v+1, total_traces, bb_cnt, fn, excitement) 

def constraint_trace(fn):
    '''
    Perform a trace on the binary in project with the input in fn.
    '''
    global shared_trace_cnt

    fn_base = os.path.basename(fn)

    content = open(fn).read()

    # get the basic block trace from qemu, this will differ slighting from angr's trace
    bb_trace = qemu_traces[fn]
    total_length = len(bb_trace)

    parent_path = project.path_generator.entry_point(add_options={simuvex.s_options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY})
    trace_group = project.path_group(immutable=False, save_unconstrained=True, save_unsat=True, paths=[parent_path])


    # did this trace produce any interesting results?
    found_one = 0

    # what the trace thinks is the next basic block
    next_move = project.entry

    # branches this trace didn't take
    trace_group.stashes['missed'] = [ ] 

    prev_loc = 0

    while len(trace_group.stashes['active']) > 0:

        bb_cnt = 0
        prev_bb = next_move

        assert len(trace_group.active) < 2


        while len(trace_group.stashes['active']) == 1:
            current = trace_group.stashes['active'][0]

            current.trim_history()
            current.state.downsize()

            if bb_cnt >= len(bb_trace):
                # sometimes angr explores one block too many. ie after a _terminate syscall angr
                # may step into the basic block after the call, this case catches that
                print_trace_stats(total_length, fn, found_one)
                shared_trace_cnt.value += 1
                return

            if current.addr == bb_trace[bb_cnt]: # the trace and angr agrees, just increment cnt
                bb_cnt += 1
            elif current.addr < binary_start_code or current.addr > binary_end_code:
                # a library or a simprocedure, we'll ignore it
                pass
            elif prev_bb == current.addr: 
                # offsets a quirk in angr, when executing a system call simprocedure we'll see the
                # same basic block get hit two times in a row
                pass 
            else:
                # the trace and angr are out of sync, likely the trace is more verbose than
                # angr and the actual occurance of the path is later on, so we wind up
                # the trace until we hit the current address
                try:
                    while bb_trace[bb_cnt] != current.addr:
                        bb_cnt += 1
                    bb_cnt += 1
                except:
                    warning("errored in trace following")
                    embed()

            # adjust prev_loc

            prev_bb = current.addr

            cur_loc = (prev_bb >> 4) ^ (prev_bb << 8) 
            cur_loc = cur_loc & (map_size - 1)
            prev_loc = cur_loc >> 1

            trace_group.drop(stash='unsat')
            trace_group.step()

        bb_trace = bb_trace[bb_cnt:]

        next_move = bb_trace[0]

        # find all the state transitions none of our traces took
        for path in trace_group.active:
            cur_loc = path.addr  

            # code pretty much copied from afl's afl-qemu-cpu-inl.h
            cur_loc = ((cur_loc >> 4) ^ (cur_loc << 8)) 
            cur_loc &= map_size - 1

            hit = bool(ord(fuzz_bitmap[cur_loc ^ prev_loc]) ^ 0xff)

            if not hit:
                if path.state.satisfiable():
                    # we're only concerned about stdin
                    indices = [ ] 
                    for i in path.guards[-1].variables:
                        if i.startswith('file_/dev/stdin_0_'):
                            indices.append(int(i.split('file_/dev/stdin_0_')[1].split('_')[0], 16))
                    if len(indices) > 0:
                        outf = dump_to_file(indices, content, prev_bb, path)
                        if outf != "":
                            found_one = 2
                else:
                    if found_one != 2:
                        found_one = 1


        trace_group.stash_not_addr(next_move, to_stash='missed')

        '''
        # check if angr found any unconstrained paths, this is most likely a crash
        if len(trace_group.stashes['unconstrained']) > 0:
            for unconstrained in trace_group.stashes['unconstrained']:
                dump_to_file(unconstrained)
                found_one = True
            trace_group.drop(stash='unconstrained')
        '''

        assert len(trace_group.stashes['active']) < 2

        # drop missed branches
        trace_group.drop(stash='missed')
        
    print_trace_stats(total_length, fn, found_one)
    shared_trace_cnt.value += 1

    if len(trace_group.errored) > 0:
        warning("some paths errored! this is most likely bad and could be a symptom of a bug!")
        for errored in trace_group.errored:
            warning(errored.error)

    return

def set_driller_simprocedures(project):

    arch = detect_arch(project.ld)

    if arch == "cgc":
        from CGCSimProc import simprocedures
    elif arch == "i386" or arch == "x86_64":
        from LibcSimProc import simprocedures 
    else:
        raise Exception("Binary is of unsupported architecture.")

    for symbol, procedure in simprocedures:
        project.set_sim_procedure(project.main_binary, symbol, procedure, None)

def main(argc, argv):
    global binary_start_code, binary_end_code
    global outputdir, inputdir, binary
    global fuzz_bitmap, map_size
    global sync_id, fuzzer_driller_dir
    global trace_cnt, total_traces
    global project
    global basedirectory
    global trace_cnt_shared

    parser = argparse.ArgumentParser(description="Find basic blocks AFL can't")
    parser.add_argument('-i', dest='inputdir', type=str, metavar="<input_dir>", help='input directoy', required=True)
    parser.add_argument('-o', dest='outputdir', type=str, metavar="<output_dir>", help='output directoy', required=True)
    parser.add_argument('-b', dest='binary', type=str, metavar="<binary>", help='binary', required=True)
    parser.add_argument('-f', dest='fuzz_bitmap', type=str, metavar="<fuzz_bitmap>", help='AFL\'s fuzz_bitmap', required=True)
    parser.add_argument('-j', default=1, dest='thread_cnt', type=int, metavar="<i>", help='number of tracer threads')
    parser.add_argument('-s', dest='sync_id', type=str, metavar="<sync_id>", help='sync id of the fuzzer invoking us', required=True)

    args = parser.parse_args()

    binary = args.binary
    inputdir = args.inputdir
    outputdir = args.outputdir
    thread_cnt = args.thread_cnt
    fuzz_bitmap_file = args.fuzz_bitmap
    sync_id = args.sync_id

    if thread_cnt > multiprocessing.cpu_count():
        die("I wouldn't recommend starting more driller processes than you have CPUs")

    ok("drilling into \"%s\" with inputs in \"%s\"" % (binary, inputdir)) 
    ok("using %d processes to get the job done" % thread_cnt)
    alert("started at %s" % time.ctime())
    if os.path.isdir(inputdir):
        inputs = os.listdir(inputdir)
        pathed_inputs = [ ]   
        for inp in inputs:
            pathed_input = os.path.join(inputdir, inp)
            if not os.path.isdir(pathed_input):
                if inp != ".traced":
                    pathed_inputs.append(pathed_input)
            
        inputs = pathed_inputs
    else:
        die("no directory \"%s\" found" % inputdir)

    try:
        os.makedirs(outputdir)
    except OSError:
        if not os.path.isdir(outputdir):
            die("cannot make output directory \"%s\"" % outputdir)
        else:
            pass
            alert("outputdir already exists, removing contents for convience")
            for f in os.listdir(outputdir):
                fpath = os.path.join(outputdir, f)
                if f != ".traced":
                    os.remove(fpath)

    fuzzer_driller_dir = "%s/../../%s_driller/queue/" % (outputdir, sync_id)
    try:
        os.makedirs(fuzzer_driller_dir)
    except OSError:
        if not os.path.isdir(fuzzer_driller_dir):
            die("cannot make fuzzer's personal driller directory \"%s\"" % fuzzer_driller_dir)

    create_and_populate_traced(outputdir)

    # open up the bitmap
    try:
        fuzz_bitmap = open(fuzz_bitmap_file).read()
        map_size = len(fuzz_bitmap)
    except IOError:
        die("fuzz_bitmap \"%s\" not found" % fuzz_bitmap_file)

    project = angr.Project(binary)

    # unlike most projects we need to allow the possibility for read to return a range
    # of values
    set_driller_simprocedures(project)

    binary_start_code = project.ld.main_bin.get_min_addr()
    binary_end_code = project.ld.main_bin.get_max_addr()
    basedirectory = os.path.dirname(argv[0])

    accumulate_traces(basedirectory, project.filename, project.ld, inputs)

    trace_cnt = 0
    total_traces = len(inputs) - len(traced)

    inputs = [i for i in inputs if i not in traced] 

    if len(inputs) > 0:
        ok("constraint tracing new inputs..")
        p = multiprocessing.Pool(thread_cnt)
        p.map(constraint_trace,  inputs)
    else:
        die("no new input available, refusing to trace")
    
    # catalogue the traces so we don't have to do the work again
    with open(os.path.join(outputdir, ".traced"), "a") as tp:
        tp.write('\n'.join(inputs))
        tp.close()

    # now that drilling is complete, let the user know some stats
    if len(os.listdir(outputdir)) < 2:
        warning("driller unable to find any satisfiable basic blocks our fuzzer couldn't reach")
    else:
        success("drilled into some basic blocks our fuzzer couldn't reach!")
        success("drilled inputs created and place into %s" % outputdir)

if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))
