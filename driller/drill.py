#!/usr/bin/env python

import angr
import sys
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

trace_cnt = 0
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

# dict of input files which have been traced in previous runs
traced = set()

# set of generated inputs to avoid duplicates
generated = set()

def dump_to_file(path):
    abspath = os.path.abspath(outputdir)
    pref = os.path.join(abspath, "driller-%x-" % path.addr)

    try:
        gen = path.state.posix.dumps(0)
    except simuvex.s_errors.SimFileError: # sometimes we don't even have symbolic data yet
        return ""

    if gen in generated:
        return ""

    generated.add(gen)

    _, outfile = tempfile.mkstemp(prefix=pref)

    fp = open(outfile, "w")
    fp.write(gen)
    fp.close()

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
    dp = open("/dev/null")

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

def update_trace_progress(numerator, denominator, fn, foundsomething):
    pcomplete = int((float(numerator) / float(denominator)) * 100)
    
    p = termcolor.colored("[*]", "cyan", attrs=["bold"])
    excitement = ""
    if foundsomething:
        excitement = termcolor.colored("!", "green", attrs=["bold"])

    print "%s trace %02d/%d, %3d%% complete, %s %s\r" % (p, trace_cnt + 1, total_traces, pcomplete, fn, excitement), 
    sys.stdout.flush()

def constraint_trace(project, basedirectory, fn):
    '''
    Perform a trace on the binary in project with the input in fn.
    '''

    fn_base = os.path.basename(fn)

    # get the basic block trace from qemu, this will differ slighting from angr's trace
    back_trace = bb_trace = qemu_traces[fn]
    total_length = len(bb_trace)

    #parent_path = project.path_generator.entry_point(add_options={simuvex.s_options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY}, remove_options={simuvex.s_options.LAZY_SOLVES})
    parent_path = project.path_generator.entry_point(add_options={simuvex.s_options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY})
    trace_group = project.path_group(immutable=False, save_unconstrained=True, save_unsat=True, paths=[parent_path])

    # did this trace produce any interesting results?
    found_one = False

    # what the trace thinks is the next basic block
    next_move = project.entry

    update_trace_progress(0, total_length, fn_base, found_one)

    # branches this trace didn't take
    trace_group.stashes['missed'] = [ ] 

    while len(trace_group.stashes['active']) > 0:

        bb_cnt = 0
        prev_bb = next_move
        while len(trace_group.stashes['active']) == 1:
            current = trace_group.stashes['active'][0]

            update_trace_progress(total_length - (len(bb_trace) - bb_cnt), total_length, fn_base, found_one)

            if bb_cnt >= len(bb_trace):
                # sometimes angr explores one block too many. ie after a _terminate syscall angr
                # may step into the basic block after the call, this case catches that
                update_trace_progress(1, 1, fn_base, found_one)
                print
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

            prev_bb = current.addr
            trace_group.drop(stash='unsat')
            trace_group.step()

        bb_trace = bb_trace[bb_cnt:]

        next_move = bb_trace[0]

        trace_group.stash_not_addr(next_move, to_stash='missed')

        # check if angr found any unconstrained paths, this is most likely a crash
        if len(trace_group.stashes['unconstrained']) > 0:
            for unconstrained in trace_group.stashes['unconstrained']:
                dump_to_file(unconstrained)
                found_one = True
            trace_group.drop(stash='unconstrained')

        assert len(trace_group.stashes['active']) < 2

        # if we just missed we check to see if another branch has encountered it
        # this *should* be a fast check because it's a hashmap
        for missed_branch in trace_group.stashes['missed']:
            if missed_branch.addr not in encountered:
                # before we waste any memory on this guy, make sure it's reachable
                if missed_branch.state.satisfiable():
                    # greedily dump the output 
                    fn = dump_to_file(missed_branch)

                    if fn != "":                        
                        if missed_branch.addr not in found:
                            found_one = True

                        found[missed_branch.addr] = fn
                        # because of things like readuntil we don't want to add anything to 
                        # the encountered list just yet

        # drop missed branches
        trace_group.drop(stash='missed')
        
    update_trace_progress(1, 1, fn_base, found_one)
    print

    if len(trace_group.errored) > 0:
        warning("some paths errored! this is most likely bad and could be a symptom of a bug!")

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
    global trace_cnt, total_traces

    if (argc != 4):
        print "usage: %s <binary> <inputdir> <outputdir>" % (argv[0])
        return 1

    binary = argv[1]
    inputdir = argv[2]
    outputdir = argv[3]

    ok("drilling into \"%s\" with inputs in \"%s\"" % (binary, inputdir)) 
    alert("started at %s" % time.ctime())
    if os.path.isdir(inputdir):
        inputs = os.listdir(inputdir)
        pathed_inputs = [ ]   
        for inp in inputs:
            pathed_input = os.path.join(inputdir, inp)
            if not os.path.isdir(pathed_input):
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

    create_and_populate_traced(outputdir)

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
    ok("constraint tracing new inputs..")
    for inputfile in inputs:
        bname = os.path.basename(inputfile)
        if bname not in traced:
            constraint_trace(project, basedirectory, inputfile)
            traced_catalogue = os.path.join(outputdir, ".traced")
            with open(traced_catalogue, "a", 0644) as tp:
                tp.write(bname + "\n")
                tp.close()
            trace_cnt += 1


    # now that drilling is complete, let the user know some stats

    if len(found) == 0:
        warning("driller unable to find any satisfiable basic blocks our fuzzer couldn't reach")
    else:
        success("drilled into %d basic block(s) our fuzzer couldn't reach!" % len(found))
        success("drilled inputs created and place into %s" % outputdir)

if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))
