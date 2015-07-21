#!/usr/bin/env pypy

'''
Frontend for driller, AFL invokes this script when it's having trouble making any progress.
'''

import angr
import driller
import driller.tasks
import driller.config as config

import argparse
import logging
import os
import sys

l = logging.getLogger("driller.drill")
l.setLevel("INFO")

def main(argv):
    parser = argparse.ArgumentParser(description="Increase AFL's code coverage")
    
    parser.add_argument("-b", dest="binary", 
                        type=str, 
                        metavar="<binary>", 
                        help="binary executable",
                        required=True)

    parser.add_argument("-i", 
                        dest="in_dir", 
                        type=str, 
                        metavar="<in_dir>", 
                        help="input directory", 
                        required=True)

    parser.add_argument("-f", 
                        dest="fuzz_bitmap", 
                        type=str, 
                        metavar="<fuzz_bitmap>", 
                        help="AFL's fuzz bitmap file",
                        required=True)

    parser.add_argument("-E",
                        dest="exit_on_eof",
                        action="store_const",
                        const=True,
                        help="exit on EOF",
                        default=False)

    args = parser.parse_args(argv)
    
    binary      = args.binary
    in_dir      = args.in_dir
    fuzz_bitmap = args.fuzz_bitmap
    exit_on_eof = args.exit_on_eof

    # use the basename, the worker will be on a different syste
    binary = os.path.basename(binary)

    for input_file in (d for d in os.listdir(in_dir) if not d.startswith('.')):
        input_data = open(os.path.join(in_dir, input_file), 'rb').read()
        driller.tasks.drill.delay(binary, input_data, open(fuzz_bitmap, 'rb').read(), exit_on_eof)

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
