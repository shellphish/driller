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
    status = termcolor.colored("*", "cyan", attrs=["bold"])
    print "[%s] %s" % (status, s)

def success(s):
    status = termcolor.colored("+", "green", attrs=["bold"])
    print "[%s] %s" % (status, s)

def alert(s):
    status = termcolor.colored("!", "yellow", attrs=["bold"])
    print "[%s] %s" % (status, s)

def warning(s):
    status = termcolor.colored("-", "red", attrs=["bold"])
    print "[%s] %s" % (status, s)

def die(s):
    status = termcolor.colored("-", "red", attrs=["bold"])
    print "[%s] %s" % (status, s)
    sys.exit(1)


encountered = {}
found = {}
qemu_traces = {}

# dict of input files which have been traced in previous runs
traced = {}

def dump_to_file(path):
    abspath = os.path.abspath(outputdir)
    pref = os.path.join(abspath, "driller-%x-" % path.addr)

    _, outfile = tempfile.mkstemp(prefix=pref)

    fp = open(outfile, "w")
    fp.write(path.state.posix.dumps(0))
    fp.close()

    return outfile

class SymbolicRead(simuvex.SimProcedure):
    '''
    A custom version of read which has a symbolic return value.
    '''

    def run(self, fd, dst, length):
        self.argument_types = {0: SimTypeFd(),
                               1: self.ty_ptr(SimTypeArray(SimTypeChar(), length)),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = SimTypeLength(self.state.arch)

        if self.state.se.max_int(length) == 0:
            return self.state.se.BVV(0, self.state.arch.bits)

        sym_length = self.state.se.BV("sym_length", self.state.arch.bits)
        self.state.add_constraints(sym_length <= length)
        self.state.add_constraints(sym_length >= 0)

        _ = self.state.posix.pos(fd)
        data = self.state.posix.read(fd, length)
        self.state.store_mem(dst, data)
        return sym_length

def detect_arch(binary):
    progdat = open(binary).read(0x800)

    if progdat[0:4] == "\x7FELF":
        machine = struct.unpack("H", progdat[0x12:0x14])[0]   # e_machine
        if machine == 0x3e:
            return "x86_64"
        if machine == 0x03:
            return "i386"
        else:
            raise Exception("Binary is of an unsupported architecture")

    if progdat[0:4] == "\x7FCGC":
        return "cgc"

    else:
        raise Exception("Binary is not an ELF")

def generate_qemu_trace(basedirectory, binary, inputfile):
    arch = detect_arch(binary)

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

def accumulate_traces(basedirectory, binary, inputs):
    global qemu_traces

    alert("accumulating traces for all %d inputs" % len(inputs))

    for inputfile in inputs:
        traces = generate_qemu_trace(basedirectory, binary, inputfile) 
        qemu_traces[inputfile] = traces

        # let's just populate encountered now
        for trace in traces:
            if trace not in encountered:
                encountered[trace] = inputfile


def create_and_populate_traced(outputdir):
    global traced

    # make the subdirectory for storing what has already been traced
    traced_dir = os.path.join(outputdir, ".traced")
    try:
        os.makedirs(traced_dir)
    except OSError:
        pass


    # populate traced
    for traced_file in os.listdir(traced_dir):
        traced[traced_file] = True

def update_trace_progress(numerator, denominator, fn, foundsomething):
    pcomplete = int((float(numerator) / float(denominator)) * 100)
    
    p = termcolor.colored("*", "cyan", attrs=["bold"])
    excitement = ""
    if foundsomething:
        excitement = termcolor.colored("!", "green", attrs=["bold"])

    print "[%s] trace %02d/%d, %3d%% complete, %s %s\r" % (p, trace_cnt + 1, total_traces, pcomplete, fn, excitement), 
    sys.stdout.flush()

def constraint_trace(project, basedirectory, fn):
    '''
    Perform a trace on the binary in project with the input in fn.
    '''

    fn_base = os.path.basename(fn)

    # get the basic block trace from qemu, this will differ slighting from angr's trace
    bb_trace = qemu_traces[fn]
    total_length = len(bb_trace)

    #parent_path = project.path_generator.entry_point(add_options={simuvex.s_options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY}, remove_options={simuvex.s_options.LAZY_SOLVES})
    parent_path = project.path_generator.entry_point(add_options={simuvex.s_options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY})
    trace_group = project.path_group(immutable=False, save_unconstrained=True, save_unsat=True, paths=[parent_path])

    # did this trace produce any interesting results?
    found_one = False

    update_trace_progress(0, total_length, fn_base, found_one)

    # branches this trace didn't take
    trace_group.stashes['missed'] = [ ] 

    while len(trace_group.stashes['active']) > 0:

        bb_cnt = 0
        while len(trace_group.stashes['active']) == 1:
            current = trace_group.stashes['active'][0]
            update_trace_progress(total_length - (len(bb_trace) - bb_cnt), total_length, fn_base, found_one)
            if current.addr == bb_trace[bb_cnt]: # the trace and angr agrees, just increment cnt
                bb_cnt += 1
            elif current.addr < binary_start_code or current.addr > binary_end_code:
                # a library or a simprocedure, we'll ignore it
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
                    found[missed_branch.addr] = fn
                    # because of things like readuntil we don't want to add anything to 
                    # the encountered list just yet
                    found_one = True

        # drop missed branches
        trace_group.drop(stash='missed')
        
    update_trace_progress(1, 1, fn_base, found_one)
    print

    if len(trace_group.errored) > 0:
        warning("some paths errored! this is most likely bad and could be a symptom of a bug!")

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
                if not os.path.isdir(fpath):
                    os.remove(fpath)

    create_and_populate_traced(outputdir)

    project = angr.Project(binary)

    # unlike most projects we need to allow the possibility for read to return a range
    # of values
    project.set_sim_procedure(project.main_binary, "read", SymbolicRead, None)


    binary_start_code = project.ld.main_bin.get_min_addr()
    binary_end_code = project.ld.main_bin.get_max_addr()
    basedirectory = os.path.dirname(argv[0])

    accumulate_traces(basedirectory, project.filename, inputs)

    trace_cnt = 0
    total_traces = len(inputs) - len(traced)
    ok("constraint tracing new inputs..")
    for inputfile in inputs:
        bname = os.path.basename(inputfile)
        if bname not in traced:
            constraint_trace(project, basedirectory, inputfile)
            traced_entry = os.path.join(outputdir, ".traced", bname)
            open(traced_entry, "w").close()
            trace_cnt += 1


    # now that drilling is complete, let the user know some stats

    if len(found) == 0:
        warning("driller unable to find any satisfiable basic blocks our fuzzer couldn't reach")
    else:
        success("drilled into %d basic block(s) our fuzzer couldn't reach!" % len(found))
        success("drilled inputs created and place into %s" % outputdir)

if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))
