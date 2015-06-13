#!/usr/bin/env python

import angr
import sys
import termcolor
import os

def ok(s):
    status = termcolor.colored("*", "cyan", attrs=["bold"])
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
    constraints = [ ] 
    for bit in range(0, stdin_bytes.length, 8)[::-1]:
        upper_bit = bit + 7
        constraints.append(stdin_bytes[upper_bit:bit] == ord(padded[pad_cnt]))
        pad_cnt += 1

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

        missed[next_branch.addr] = False

        # if we just missed we check to see if another branch has encountered it
        if missed.get(missed_branch.addr) == None:
            # it appears no one has touched this branch we'll let every one know it's
            # in sight for us
            missed[missed_branch.addr] = fn

        ok(next_branch)
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
    if (argc != 3):
        print "usage: %s <binary> <inputdir>" % (argv[0])
        return 1

    binary = argv[1]
    inputdir = argv[2]

    ok("drilling into \"%s\" with inputs in \"%s\"" % (binary, inputdir)) 
    if os.path.isdir(inputdir):
        inputs = os.listdir(inputdir)
    else:
        die("no directory \"%s\" found" % inputfile)

    project = angr.Project(binary)

    for inputfile in inputs:
        path = os.path.join(inputdir, inputfile)
        print trace_branches(project, open(path).read(), inputfile)

    print map(hex, filter(lambda v: missed[v], missed.keys()))


if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))
