#!/usr/bin/env python

import driller.config as config
import os
import sys

def main(argv):

    if len(argv) < 2:
        print "%s <n-workers>" % argv[0]
        return 1

    n = int(argv[1])

    # verify that config.QEMU_DIR is sane
    if not os.path.isdir(config.QEMU_DIR):
        print "the qemu directory specified in the config is not a directory"
        return 1

    if "driller-qemu-cgc" not in os.listdir(config.QEMU_DIR):
        print "the qemu directory does not contain any file by the name of 'driller-qemu-cgc'"
        return 1

    args = ["celery", "-A", "driller.tasks", "worker", "-c", n, "--loglevel=info"]

    os.execv(args[0], args)




if __name__ == "__main__":
    sys.exit(main(sys.argv))
