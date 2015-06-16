#!/usr/bin/env python

import angr
import sys
import termcolor
import os
import tempfile
import subprocess
import simuvex
from simuvex.s_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength
from IPython import embed

binary_start_code = None
binary_end_code = None

def ok(s):
    status = termcolor.colored("*", "cyan", attrs=["bold"])
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
missed = {}
qemu_traces = {}

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

        sym_length = self.state.se.BV("read_length", self.state.arch.bits)

        self.state.se.add(sym_length <= length)

        self.state.se.add(sym_length >= 0)

        _ = self.state.posix.pos(fd)
        #data = self.state.posix.read(fd, sym_length)
        data = self.state.posix.read(fd, length)
        self.state.store_mem(dst, data)
        return sym_length


def patch_symbolic_read(proj):
    '''
    patch in a custom symbolic read into the loader 
    '''

    main_bin = proj.main_binary
    proj.set_sim_procedure(main_bin, "read", SymbolicRead, None)


def generate_qemu_trace(basedirectory, binary, inputfile):
    qemu_path = os.path.join(basedirectory, "qemu", "qemu-x86_64")
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
        #full_inputfile = os.path.join(
        qemu_traces[inputfile] = generate_qemu_trace(basedirectory, binary, inputfile)

def in_any_trace(addr):
    for trace_f in qemu_traces:
        if addr in qemu_traces[trace_f]:
            return True

    return False

def follow_trace_until_split(path, trace, total_length):
    '''
    trace is qemu's basic block trace so it will have slightly more information than
    we would like.

    we return the possible branches and an updated trace 
    '''

    bb_cnt = 0
    successors = [path]

    while len(successors) == 1:
        current = successors[0]
        update_trace_progress(total_length - (len(trace) - bb_cnt), total_length)
        if current.addr == trace[bb_cnt]: # the trace and angr agrees, just increment cnt
            bb_cnt += 1
        elif current.addr < binary_start_code or current.addr > binary_end_code:
            # a library or a simprocedure, we'll ignore it
            pass
        else:
            # the trace and angr are out of sync, likely the trace is more verbose than
            # angr and the actual occurance of the path is later on, so we wind up
            # the trace until we hit the current address
            while trace[bb_cnt] != current.addr:
                bb_cnt += 1
            bb_cnt += 1

        successors = current.successors

    return successors, trace[bb_cnt:]

def update_trace_progress(numerator, denominator):
    bar_length = 50

    current = int((float(numerator) / float(denominator)) * bar_length)
    
    complete  = "#" * current
    remainder = (bar_length - current) * " "

    print "[%s%s]\r" % (complete, remainder), 
    sys.stdout.flush()

def trace_branches(project, basedirectory, fn):

    # get the basic block trace from qemu, this will differ slighting from angr's jump 
    # trace
    bb_trace = qemu_traces[fn]

    total_length = len(bb_trace)

    next_branch = project.path_generator.entry_point(add_options={simuvex.s_options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY})

    multiple_branches = True
    while multiple_branches:


        branches, bb_trace = follow_trace_until_split(next_branch, bb_trace, total_length)
        next_move = bb_trace[0]

        multiple_branches = len(branches) > 1
        if not multiple_branches:
            print "[%s]" % ("#" * 50)
            break

        branch1 = branches[0]
        branch2 = branches[1]

        branch1_taker = False
        branch2_taker = False 
        if next_move == branch1.addr:
            branch1_taker = True
        if next_move == branch2.addr:
            branch2_taker = True

        assert branch1_taker or branch2_taker
        assert not (branch1_taker and branch2_taker)

        if branch1_taker:
            next_branch = branch1
            missed_branch = branch2
        else:
            next_branch = branch2
            missed_branch = branch1

        # if we've encountered a branch we mark it
        encountered[next_branch.addr] = fn

        # remove branch we encountered from our missed branches dict
        if next_branch.addr in missed:
            del missed[next_branch.addr]

        # if we just missed we check to see if another branch has encountered it
        # this *should* be a fast check because it's a hashmap
        if missed_branch.addr not in encountered:
            # because of memory issues we also make sure it isn't in any of the traces 
            if not in_any_trace(missed_branch.addr):
                # final check, is it even satisfiable?
                if missed_branch.state.satisfiable():
                    # possible we could just generate the new input here
                    if missed_branch.addr in missed:
                        missed[missed_branch.addr].append(missed_branch)
                    else:
                        missed[missed_branch.addr] = [missed_branch]

    return

def main(argc, argv):
    global binary_start_code, binary_end_code

    if (argc != 4):
        print "usage: %s <binary> <inputdir> <outputdir>" % (argv[0])
        return 1

    binary = argv[1]
    inputdir = argv[2]
    outputdir = argv[3]

    ok("drilling into \"%s\" with inputs in \"%s\"" % (binary, inputdir)) 
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
            alert("outputdir already exists, removing contents for convience")
            for f in os.listdir(outputdir):
                fpath = os.path.join(outputdir, f)
                os.remove(fpath)

    project = angr.Project(binary)
    patch_symbolic_read(project)
    binary_start_code = project.ld.main_bin.get_min_addr()
    binary_end_code = project.ld.main_bin.get_max_addr()
    basedirectory = os.path.dirname(argv[0])

    accumulate_traces(basedirectory, project.filename, inputs)

    trace_cnt = 0
    for inputfile in inputs:
        ok("[%02d/%d] tracing input from \"%s\"" % (trace_cnt + 1, len(inputs), inputfile))
        trace_branches(project, basedirectory, inputfile)
        trace_cnt += 1


    # now that we've found some branches which our fuzzer missed, let's drill into them
    alert("found %d basic block(s) our fuzzer had trouble reaching, drilling!" % len(missed))


    alert("driller attempting to break into " + str(map(hex, missed.keys())))

    for missed_addr in missed:
        angr_paths = missed[missed_addr]
        cur_path = 0
        satisfied = False
        while not satisfied and cur_path < len(angr_paths):
            angr_path = angr_paths[cur_path]
            if angr_path.state.satisfiable():
                filename = "driller-%x" % angr_path.addr
                outname = os.path.join(outputdir, filename)
                fp = open(outname, "w")
                fp.write(angr_path.state.posix.dumps(0))
                fp.close()
                ok("new input in %s!" % outname)
                satisfied = True

            cur_path += 1

        if not satisfied:
            warning("path at 0x%x is not satisfiable" % missed_addr)

    ok("drilled inputs created and place in %s" % outputdir)

if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))
