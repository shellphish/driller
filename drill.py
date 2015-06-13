#!/usr/bin/env python

import angr
import sys
import termcolor

def ok(s):
    status = termcolor.colored("*", "cyan", attrs=["bold"])
    print "[%s] %s" % (status, s)

def die(s):
    status = termcolor.colored("-", "red", attrs=["bold"])
    print "[%s] %s" % (status, s)
    sys.exit(1)


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

def path_jump_targets(project, inputstream):


    next_branch = project.path_generator.entry_point()

    while True:
        branches = windup_to_branch(next_branch)

        if len(branches) == 0:
            return

        branch1 = branches[0]
        branch2 = branches[1]

        branch1_taker = branch_for_input(branch1, inputstream)
        branch2_taker = branch_for_input(branch2, inputstream)

        assert not (branch1_taker and branch2_taker)

        if branch1_taker:
            next_branch = branch1
        else:
            next_branch = branch2

        print next_branch


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
        print "usage: %s <binary> <inputfile>" % (argv[0])
        return 1

    binary = argv[1]
    inputfile = argv[2]

    ok("drilling into %s with inputfile %s" % (binary, inputfile)) 
    try:
        inputstream = open(inputfile).read()
    except IOError:
        die("file \"%s\" does not exist" % inputfile)

    project = angr.Project(binary)
    entry_point = project.path_generator.entry_point()

    ok("entry point found at 0x%x" % entry_point.addr)

    print path_jump_targets(project, inputstream)


if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))
