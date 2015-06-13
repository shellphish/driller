#!/usr/bin/env python

import angr
import sys
import termcolor
import os

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

def branch_for_input(branch, inputstream):

    stdin_bytes = branch.state.posix.files[0].all_bytes()

    stdin_bytes_cnt = stdin_bytes.length / 8

    padded = inputstream.ljust(stdin_bytes_cnt, "\x00")
    pad_cnt = 0
    constraints = [ stdin_bytes == branch.state.BVV(padded) ] 

    return branch.state.se.satisfiable(extra_constraints = constraints)

def trace_branches(project, inputstream, fn):


    next_branch = project.path_generator.entry_point()
    branches = windup_to_branch(next_branch)

    not_taken = [ ] 
    taken = [ ] 

    while len(branches) == 2:

        branch1 = branches[0]
        branch2 = branches[1]

        branch1_taker = branch_for_input(branch1, inputstream)
        branch2_taker = branch_for_input(branch2, inputstream)

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
            missed[missed_branch.addr] = (missed_branch, fn)

        #ok(next_branch)
        branches = windup_to_branch(next_branch)

    return (taken, not_taken)

def windup_to_branch(path):
    '''
    windup the path until we hit our first branch, return a list of branches
    '''

    current_path = path
    branches = []
    while len(branches) < 2:
        branches = current_path.successors
        try:
            current_path = branches[0]
        except IndexError:
            return []

    return branches

def main(argc, argv):
    if (argc != 4):
        print "usage: %s <binary> <inputdir> <outputdir>" % (argv[0])
        return 1

    binary = argv[1]
    inputdir = argv[2]
    outputdir = argv[3]

    ok("drilling into \"%s\" with inputs in \"%s\"" % (binary, inputdir)) 
    if os.path.isdir(inputdir):
        inputs = os.listdir(inputdir)
    else:
        die("no directory \"%s\" found" % inputdir)

    try:
        os.makedirs(outputdir)
    except OSError:
        if not os.path.isdir(outputdir):
            die("cannot make output directory \"%s\"" % outputdir)


    project = angr.Project(binary)

    for inputfile in inputs:
        path = os.path.join(inputdir, inputfile)
        trace_branches(project, open(path).read(), inputfile)


    # now that we've found some branches which our fuzzer missed, let's drill into them
    alert("found %d basic blocks our fuzzer had trouble reaching, drilling into them!" % len(missed))

    # here we would get fuzzer stats to figure out which input id these new inputs should
    # be
    file_id = 0

    for missed_addr in missed:
        angr_path, input_file = missed[missed_addr]
        if angr_path.state.satisfiable():
            filename = "driller-%d" % file_id
            outname = os.path.join(outputdir, filename)
            fp = open(outname, "w")
            fp.write(angr_path.state.posix.dumps(0))
            fp.close()
            ok("new input in %s!" % outname)
            file_id += 1

        else:
            warning("path at %x is not satisfiable" % missed_addr)
            continue

    ok("drilled inputs created and place in %s" % outputdir)

if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))
