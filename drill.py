#!/usr/bin/env python

import angr
import sys
import termcolor
import os
import tempfile
import subprocess
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

def follow_trace_until_split(path, trace):
    '''
    trace is qemu's basic block trace so it will have slightly more information than
    we would like.

    we return the possible branches and an updated trace 
    '''

    bb_cnt = 0
    successors = [path]

    while len(successors) == 1:
        current = successors[0]
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


def trace_branches(project, basedirectory, fn):

    # get the basic block trace from qemu, this will differ slighting from angr's jump 
    # trace
    bb_trace = generate_qemu_trace(basedirectory, project.filename, fn)

    next_branch = project.path_generator.entry_point()

    branches, bb_trace = follow_trace_until_split(next_branch, bb_trace)

    next_move = bb_trace[0]

    not_taken = [ ] 
    taken = [ ] 

    inputstream = open(fn).read()

    while len(branches) == 2:

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

        not_taken.append(missed_branch)
        taken.append(next_branch)
        
        # if we've encountered a branch we mark it
        encountered[next_branch.addr] = fn

        # remove branch we encountered from our missed branches dict
        if next_branch.addr in missed:
            del missed[next_branch.addr]

        # if we just missed we check to see if another branch has encountered it
        if missed_branch.addr not in encountered:
            # if not, let the system know we have this branch in our sights
            if missed_branch.addr in missed:
                missed[missed_branch.addr].append(missed_branch)
            else:
                missed[missed_branch.addr] = [missed_branch]

        branches, bb_trace = follow_trace_until_split(next_branch, bb_trace)
        next_move = bb_trace[0]

    return (taken, not_taken)

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
                pathed_inputs.append(inp)
            
        inputs = pathed_inputs
    else:
        die("no directory \"%s\" found" % inputdir)

    try:
        os.makedirs(outputdir)
    except OSError:
        if not os.path.isdir(outputdir):
            die("cannot make output directory \"%s\"" % outputdir)


    project = angr.Project(binary)
    binary_start_code = project.ld.main_bin.get_min_addr()
    binary_end_code = project.ld.main_bin.get_max_addr()
    basedirectory = os.path.dirname(argv[0])

    for inputfile in inputs:
        ok("tracing input from \"%s\"" % inputfile)
        path = os.path.join(inputdir, inputfile)
        trace_branches(project, basedirectory, path)


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
