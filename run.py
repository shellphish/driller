#!/usr/bin/env python

import fuzz
import argparse
import multiprocessing
import os
import sys
import shutil
import time

import logging
l = logging.getLogger("largescale")
l.setLevel("INFO")

'''
Large scale test script. Should just require pointing it at a directory and specifying
the number of number of jobs which can run at a time and the fuzzers per job
'''

def worker(q):
    while not q.empty():
        p = q.get()
        start_fuzzing(*p)

    return 0
        
def start_fuzzing(binary_path, out_dir, fuzzers):
    binary = os.path.basename(binary_path)
    idx = binary.rindex("_") 
    identifier = binary[:idx]

    l.info("working on binary with id \"%s\"", identifier)

    # make a solve directory
    work_dir = os.path.join(out_dir, identifier)
    l.debug("work_dir: %s", work_dir)

    try:
        os.makedirs(work_dir)
    except OSError:
        l.warning("unable to making work directory for challenge %s", identifier)

    # copy the binary over
    our_binary = os.path.join(work_dir, binary)
    shutil.copy(binary_path, our_binary)

    # make an input directory with just the file fuzz
    input_dir  = os.path.join(work_dir, "input")
    try:
        os.makedirs(input_dir)
    except OSError:
        l.warning("unable to make input directory for challenge %s", identifier)

    input_file = os.path.join(input_dir, "fuzz")

    with open(input_file, 'wb') as f:
        f.write("fuzz")

    # output file directory
    fuzz_out_dir = os.path.join(work_dir, "sync")

    # redirect output    
    fuzz_log = os.path.join(work_dir, "fuzz.log")

    with open(fuzz_log, 'wb') as f:
        saved = sys.stdout
        sys.stdout = f

        # start fuzzing
        fuzz.start(our_binary, input_dir, fuzz_out_dir, fuzzers, work_dir)
        sys.stdout = saved

    return 0

def start(binary_dir, out_dir, fuzz_jobs, fuzzers_per_job):

    p = multiprocessing.Pool(fuzz_jobs)

    pathed_binaries = [ ] 
    binaries = os.listdir(binary_dir)
    for binary in binaries:
        if binary.startswith("."):
            continue 
        identifier = binary[:binary.rindex("_")]
        # remove IPC binaries from largescale testing
        if (identifier + "_02") not in binaries:
            pathed_binaries.append(os.path.join(binary_dir, binary))

    l.info("%d binaries found", len(pathed_binaries))
    l.debug("binaries: %r", pathed_binaries)

    # create a queue and put all the binaries there
    queue = multiprocessing.Queue()
    for binary in pathed_binaries:
        queue.put((binary, out_dir, fuzzers_per_job))

    procs = [ ] 
    for i in range(fuzz_jobs):
        p = multiprocessing.Process(target=worker, args=(queue,))
        procs.append(p) 
        p.start()

    for p in procs:
        p.join()

def main():
    global fuzzers_per_job
    global out_dir

    parser = argparse.ArgumentParser(description="Largescale Tester") 

    parser.add_argument("-i", dest="binary_dir",
                        type=str,
                        metavar="<binary_dir>",
                        help="directory of challenge binaries",
                        required=True)

    parser.add_argument("-o", dest="out_dir",
                        type=str,
                        metavar="<out_dir>",
                        help="working directories",
                        required=True)

    parser.add_argument("-n", dest="fuzz_jobs",
                        type=int,
                        metavar="<fuzz_jobs>",
                        help="number of simultaneous fuzzing jobs",
                        required=True)

    parser.add_argument("-j", dest="fuzzers_per_job",
                        type=int,
                        metavar="<fuzzers_per_job>",
                        help="number of fuzzers per job",
                        required=True)

    args = parser.parse_args()

    binary_dir      = args.binary_dir
    out_dir         = args.out_dir
    fuzz_jobs       = args.fuzz_jobs
    fuzzers_per_job = args.fuzzers_per_job

    start(binary_dir, out_dir, fuzz_jobs, fuzzers_per_job)

if __name__ == "__main__":
    sys.exit(main())
