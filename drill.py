#!/usr/bin/env pypy

'''
Frontend for driller, AFL invokes this script when it's having trouble making any progress.
'''

import angr
import driller
import driller.tasks

import argparse
import logging
import os
import sys

l = logging.getLogger("drill")
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

    parser.add_argument("-o", 
                        dest="out_dir", 
                        type=str, 
                        metavar="<out_dir>", 
                        help="output directory",
                        required=True)

    parser.add_argument("-f", 
                        dest="fuzz_bitmap", 
                        type=str, 
                        metavar="<fuzz_bitmap>", 
                        help="AFL's fuzz bitmap file",
                        required=True)

    parser.add_argument("-q",
                        dest="qemu_dir",
                        type=str,
                        metavar="<qemu_dir>",
                        help="installation directory of driller's qemus",
                        required=True)

    parser.add_argument("-j",
                        dest="proc_cnt",
                        type=int,
                        metavar="<proc_cnt>",
                        help="number of processes to invoke",
                        default=1)

    parser.add_argument("-s",
                        dest="sync_dir",
                        type=str,
                        metavar="<sync_dir>",
                        help="AFL's sync directory",
                        default=None)
        

    args = parser.parse_args(argv)
    
    binary      = args.binary
    in_dir      = args.in_dir
    out_dir     = args.out_dir
    fuzz_bitmap = args.fuzz_bitmap
    qemu_dir    = args.qemu_dir
    proc_cnt    = args.proc_cnt
    sync_dir    = args.sync_dir

    for input_file in (d for d in os.listdir(in_dir) if not d.startswith('.')):
        input_data = open(os.path.join(in_dir, input_file), 'rb').read()
        driller.tasks.drill.delay(binary, input_data, out_dir, open(fuzz_bitmap, 'rb').read(), qemu_dir)

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
