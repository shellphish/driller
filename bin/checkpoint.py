#!/usr/bin/env pypy

import sys

'''
check if a bitmap enountered a given state transition
'''

def hit(bitmap, addr1, addr2):

    prev_loc = addr1
    prev_loc = (prev_loc >> 4) ^ (prev_loc << 8)
    prev_loc &= len(bitmap) - 1 
    prev_loc = prev_loc >> 1

    cur_loc = addr2
    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8)
    cur_loc &= len(bitmap) - 1 

    hit = bool(ord(bitmap[cur_loc ^ prev_loc]) ^ 0xff)

    return hit


def main(argc, argv):

    if argc < 4:
        print "usage: %s <bitmap> <addr1> <addr2>" % argv[0]
        return 1

    bitmap = open(argv[1]).read()
    addr1  = int(argv[2], 16)
    addr2  = int(argv[3], 16)

    if hit(bitmap, addr1, addr2):
        print "The state transition was hit"
    else:
        print "The state transition was not hit"

if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))
