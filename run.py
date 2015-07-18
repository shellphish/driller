#!/usr/bin/env python

import argparse
import redis
import driller.tasks
import os
import subprocess
import signal
import sys
import multiprocessing

import driller.config as config

import logging

l = logging.getLogger("run")
l.setLevel("DEBUG")

# global list of processes so we can kill them on SIGINT
procs = [ ] 

def terminate(signal, frame):
    map(lambda p: p.terminate(), procs)
    sys.exit(0)

def start_afl(afl_path, binary, in_dir, out_dir, fuzz_id, dictionary=None, memory="8G",
                driller=None, qemu_path=None):

    args = [afl_path]

    args += ["-i", in_dir]
    args += ["-o", out_dir]
    args += ["-m", memory]
    args += ["-Q"]
    if fuzz_id == 0:
        args += ["-M", "fuzzer-master"]
        outfile = "fuzzer-master.log"
    else:
        args += ["-S", "fuzzer-%d" % fuzz_id]
        outfile = "fuzzer-%d.log" % fuzz_id

    if dictionary is not None:
        args += ["-x", dictionary]

    if driller is not None:
        args += ["-D", driller]

    args += ["--", binary]

    l.debug("execing: %s > %s" % (' '.join(args), outfile))

    fp = open(outfile, "w")
    return subprocess.Popen(args, stdout=fp)

def start_afl_master(afl_path, binary, in_dir, out_dir, dictionary=None):

    return start_afl(afl_path, binary, in_dir, out_dir, fuzz_id=0, dictionary=dictionary)

def start_afl_slave(afl_path, binary, in_dir, out_dir, fuzz_id, dictionary=None):

    return start_afl(afl_path, binary, in_dir, out_dir, fuzz_id, dictionary=dictionary)

def start_afl_driller(afl_path, binary, in_dir, out_dir, fuzz_id, driller, qemu_path, 
                dictionary=None):

    return start_afl(afl_path, binary, in_dir, out_dir, fuzz_id, dictionary=dictionary, 
                driller=driller, qemu_path=qemu_path)

def clear_redis(identifier):
    redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)

    # delete all the catalogue entries
    redis_inst.delete("%s-catalogue" % identifier)

    # delete all the traced entries
    redis_inst.delete("%s-traced" % identifier)

def listen(queue_dir, channel):
    l.info("subscring to redis channel %s" % channel)

    redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)
    p = redis_inst.pubsub()

    p.subscribe(channel)

    input_cnt = 0

    for msg in p.listen():
        if msg['type'] == 'message':
            real_msg = pickle.loads(msg['data'])
            out_filename = "driller-%d-%x-%x" % real_msg['meta']
            l.info("dumping new input to %s" % out_filename)
            afl_name = "id:%06d,src:%s" % (input_cnt, out_filename)
            out_file = os.path.join(queue_dir, afl_name)

            with open(out_file, 'wb') as ofp:
                ofp.write(real_msg['data'])

            input_cnt += 1

def start_redis_listener(identifier, out_dir):
    driller_queue_dir = os.path.join(out_dir, "driller", "queue")
    channel = "%s-generated" % identifier

    p = multiprocessing.Process(target=listen, args=(driller_queue_dir, channel,))
    p.start()
    return p

def main():
    global procs

    parser = argparse.ArgumentParser(description="Driller")

    base = os.path.dirname(__file__)

    parser.add_argument("-b", dest="binary",
                        type=str,
                        metavar="<binary>",
                        help="binary executable to drill",
                        required=True)

    parser.add_argument("-i", dest="in_dir",
                        type=str,
                        metavar="<in_dir>",
                        help="input directory",
                        required=True)

    parser.add_argument("-o", dest="out_dir",
                        type=str,
                        metavar="<out_dir>",
                        help="output directory",
                        required=True)

    parser.add_argument("-n", dest="afl_count",
                        type=int,
                        metavar="<afl_count>" ,
                        help="number of AFL instances to use",
                        required=True)

    args = parser.parse_args()

    binary_path  = args.binary
    in_dir       = args.in_dir
    out_dir      = args.out_dir
    afl_count    = args.afl_count

    # the path to AFL capable of calling driller
    afl_path      = os.path.join(base, "driller-afl-fuzz")
    # the AFL build path for afl-qemu-trace-*
    afl_path_var  = os.path.join(base, "build", "afl")
    # path to the qemu binaries
    qemu_path     = os.path.join(base, "driller-qemu")
    # path to the drill script
    driller_path  = os.path.join(base, "drill.py")
    # redis channel id
    channel_id    = os.path.basename(binary_path)

    l.debug("afl_path: %s" % afl_path)
    l.debug("qemu_path: %s" % qemu_path)
    l.debug("driller_path: %s" % driller_path)
    l.debug("AFL_PATH_ENV: %s" % afl_path_var)
    l.debug("channel_id: %s" % channel_id) 

    # clear redis database
    clear_redis(channel_id)

    # look for a dictionary, if one doesn't exist create it with angr

    # set environment variable for the AFL_PATH
    os.environ['AFL_PATH'] = afl_path_var

    # spin up the master AFL instance
    procs.append(start_afl_master(afl_path, binary_path, in_dir, out_dir))

    if afl_count > 1:
        procs.append(start_afl_driller(afl_path, binary_path, in_dir, out_dir, 1, driller_path, qemu_path))
    else:
        l.warning("only one AFL instance was chosen to be spun up, driller will never be invoked")

    # only spins up an AFL instances if afl_count > 1
    for n in range(2, afl_count):
        procs.append(start_afl_slave(afl_path, binary_path, in_dir, out_dir, n))

    # spin up the redis listener
    procs.append(start_redis_listener(channel_id, out_dir))

    # setup signal handler
    signal.signal(signal.SIGINT, terminate)

    while True:
        raw_input("")
        # show_afl_stats(out_dir)


if __name__ == "__main__":
    main()
