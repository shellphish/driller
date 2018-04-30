#!/usr/bin/env python

import os
import sys
import resource
import subprocess
import nodeprofile
import driller.config as config

import logging

l = logging.getLogger("driller.node")

def check_exec(d, p):
    path = os.path.join(d, p)
    return not os.path.isdir(path) and os.access(path, os.X_OK)

def binary_dir_sane():
    if not os.path.isdir(config.BINARY_DIR):
        l.error("the binary directory specified in the config is not a directory")
        return False

    if not any(filter(lambda x: check_exec(config.BINARY_DIR, x), os.listdir(config.BINARY_DIR))):
        l.error("no binary files detected in binary directory specified")
        return False

    return True

def driller_node(n, outfile, errfile):

    if not binary_dir_sane():
        return 1

    l.info("spinning up a driller node with %d workers", n)
    args = ["celery", "-A", "driller.tasks", "worker", "-c", str(n), "-Q", "driller", "--loglevel=info", "-n", "driller.%h"]

    with open(outfile, "w") as o:
        with open(errfile, "w") as e:
            subprocess.Popen(args, stdout=o, stderr=e)

def fuzzer_node(n, outfile, errfile):

    if not binary_dir_sane():
        return 1

    l.info("spinning up a fuzzer node with %d workers", n)

    args = ["celery", "-A", "driller.tasks", "worker", "-c", str(n), "-Q", "fuzzer", "--loglevel=info", "-Ofair", "-n", "fuzzer.%h"]

    with open(outfile, "w") as o:
        with open(errfile, "w") as e:
            subprocess.Popen(args, stdout=o, stderr=e)

def main(argv):
    l.setLevel("INFO")

    if nodeprofile.DRILLER_WORKERS:
        driller_node(nodeprofile.DRILLER_WORKERS, "driller-out.log", "driller-err.log")
    if nodeprofile.FUZZER_WORKERS:
        fuzzer_node(nodeprofile.FUZZER_WORKERS, "fuzzer-out.log", "fuzzer-err.log")

if __name__ == "__main__":
    sys.exit(main(sys.argv))
