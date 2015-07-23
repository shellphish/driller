#!/usr/bin/env python

import logging
import logconfig

# silence these loggers
logging.getLogger().setLevel("CRITICAL")
logging.getLogger("driller.fuzz").setLevel("INFO")

l = logging.getLogger("driller.run")
l.setLevel("INFO")

import os
import sys
import redis
import fuzzer.tasks
import driller.config as config

'''
Large scale test script. Should just require pointing it at a directory full of binaries.
'''

def start(binary_dir):

    jobs = [ ]
    binaries = os.listdir(binary_dir)
    for binary in binaries:
        if binary.startswith("."):
            continue 

        pathed_binary = os.path.join(binary_dir, binary)
        if os.path.isdir(pathed_binary):
            continue
        if not os.access(pathed_binary, os.X_OK):
            continue

        identifier = binary[:binary.rindex("_")]
        # remove IPC binaries from largescale testing
        if (identifier + "_02") not in binaries:
            jobs.append(binary)

    l.info("%d binaries found", len(jobs))
    l.debug("binaries: %r", jobs)

    # send all the binaries to the celery queue
    for binary in jobs:
        fuzzer.tasks.fuzz.delay(binary)

def listen():

    redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)
    p = redis_inst.pubsub()

    p.subscribe("crashes")

    for msg in p.listen():
        if msg['type'] == 'message':
            print "crash found for '%s'" % msg['data'] 

def main(argv):

    if len(argv) < 2:
        print "usage: %s <binary_dir>" % argv[0]
        return 1

    binary_dir = sys.argv[1]

    start(binary_dir)
    listen()

if __name__ == "__main__":
    sys.exit(main(sys.argv))
