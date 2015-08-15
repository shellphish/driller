#!/usr/bin/env pypy

'''
Frontend for driller, AFL invokes this script when it's having trouble making any progress.
'''

import logging
import logconfig

# silence these loggers
logging.getLogger().setLevel("CRITICAL")

l = logging.getLogger("driller.drill")
l.setLevel("INFO")

import angr
import driller
import driller.tasks
import driller.config as config

import os
import sys
import time
import argparse

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

    args = parser.parse_args(argv)
    
    binary      = args.binary
    in_dir      = args.in_dir
    fuzz_bitmap = args.fuzz_bitmap

    # use the basename, the worker will be on a different syste
    binary = os.path.basename(binary)

    inputs = filter(lambda d: not d.startswith('.'), os.listdir(in_dir))
    l.info("[%s] Drilling job requested at %s with %d inputs sent", binary, time.ctime(), len(inputs))

    for input_file in inputs:
        input_data = open(os.path.join(in_dir, input_file), 'rb').read()
        driller.tasks.drill.delay(binary, input_data, open(fuzz_bitmap, 'rb').read())

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
