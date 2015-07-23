#!/usr/bin/env python

import os
import sys
import multiprocessing
import driller.config as config

def check_exec(d, p):
    path = os.path.join(d, p)
    return not os.path.isdir(path) and os.access(path, os.X_OK)

def driller_node():
    n = multiprocessing.cpu_count()

    # verify that config.QEMU_DIR is sane
    if not os.path.isdir(config.QEMU_DIR):
        print "the qemu directory specified in the config is not a directory"
        return 1

    if "driller-qemu-cgc" not in os.listdir(config.QEMU_DIR):
        print "the qemu directory does not contain any file by the name of 'driller-qemu-cgc'"
        return 1

    # verify that config.BINARY_DIR contains some binaries
    if not os.path.isdir(config.BINARY_DIR):
        print "the binary directory specified in the config is not a directory"
        return 1

    if not any(filter(lambda x: check_exec(config.BINARY_DIR, x), os.listdir(config.BINARY_DIR))):
        print "no binary files detected in binary directory specified, failing fast"
        return 1

    print "[#] spinning up a driller node with %d workers" % n
    args = ["celery", "-A", "driller.tasks", "worker", "-c", str(n), "-Q", "driller", "--loglevel=info"]

    os.execvp(args[0], args)

def fuzzer_node():
    n = multiprocessing.cpu_count()

    n /= config.FUZZER_INSTANCES

    print "[#] spinning up a fuzzer node with %d workers" % n
    args = ["celery", "-A", "fuzzer.tasks", "worker", "-c", str(n), "-Q", "fuzzer", "--loglevel=info"]

    os.execvp(args[0], args)

def main(argv):

    if len(argv) < 2:
        print "%s [driller|fuzzer]" % argv[0]
        return 1

    node_type = argv[1]

    if node_type == "driller":
        driller_node()
    elif node_type == "fuzzer":
        fuzzer_node()
    else:
        print "unknown node type specified"
        return 1

if __name__ == "__main__":
    sys.exit(main(sys.argv))
