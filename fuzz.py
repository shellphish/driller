#!/usr/bin/env python

import angr
import driller.config as config

import argparse
import redis
import driller.tasks
import os
import subprocess
import signal
import sys
import multiprocessing
import cPickle as pickle
import time
import tempfile
import termcolor
import string

import logging

l = logging.getLogger("driller.fuzz")

# global list of processes so we can kill them on SIGINT
procs = [ ] 

start_time = 0

### EXIT HANDLERS

def kill_procs():
    map(lambda p: p.terminate(), procs)

def terminate(signal, frame):
    kill_procs()
    sys.exit(0)

def handle_timeout(signal, frame):
    global crash_found
    # end searching
    l.warning("timeout hit! giving up on this binary")
    crash_found = True

### DICTIONARY CREATION

def hexescape(s):
    out = [ ]
    acceptable = string.letters + string.digits + " ."
    for c in s:
        if c not in acceptable:
            out.append("\\x%02x" % ord(c))
        else:
            out.append(c)

    return ''.join(out)

def create_dict(binary, outfile):
    b = angr.Project(binary)
    cfg = b.analyses.CFG(keep_input_state=True, enable_advanced_backward_slicing=True)

    string_references = [ ]
    for f in cfg.function_manager.functions.values():
        try:
            string_references.append(f.string_references())
        except ZeroDivisionError:
            pass

    string_references = sum(string_references, [])

    strings = [] if len(string_references) == 0 else zip(*string_references)[1]

    if len(strings) > 0:
        with open(outfile, 'wb') as f:
            for i, string in enumerate(strings):
                # AFL has a limit of 128 bytes per dictionary entries
                if len(string) <= 128:
                    s = hexescape(string)
                    f.write("driller_%d=\"%s\"\n" % (i, s))

        return True

    return False

### BEHAVIOR TESTING

def crash_test(qemu_dir, binary):

    args = [os.path.join(qemu_dir, "driller-qemu-cgc"), binary]

    fd, jfile = tempfile.mkstemp()
    os.close(fd)

    with open(jfile, 'w') as f:
        f.write("fuzz")

    with open(jfile, 'r') as i:
        with open('/dev/null', 'w') as o:
            p = subprocess.Popen(args, stdin=i, stdout=o)
            p.wait()

            if p.poll() < 0:
                ret = True
            else:
                ret = False

    return ret

### AFL SPAWNERS

def start_afl_instance(afl_path, binary, in_dir, out_dir, fuzz_id, dictionary=None, memory="8G",
                driller=None, eof_termination=False):

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

    if eof_termination:
        args += ["-E"]

    args += ["--", binary]

    l.debug("execing: %s > %s" % (' '.join(args), outfile))

    # kind of gross hack to get the output directory
    work_dir = os.path.dirname(out_dir[:-1])

    outfile = os.path.join(work_dir, outfile)
    fp = open(outfile, "w")

    return subprocess.Popen(args, stdout=fp)

def start_afl(afl_path, binary_path, in_dir, out_dir, afl_count, driller_path, dictionary, eof_exit):
    global procs

    # spin up the master AFL instance
    master = start_afl_instance(afl_path, 
                                binary_path,
                                in_dir,
                                out_dir,
                                fuzz_id=0, # the master fuzzer
                                dictionary=dictionary,
                                eof_termination=eof_exit)
    procs.append(master)

    if afl_count > 1:
        driller = start_afl_instance(afl_path,
                                     binary_path,
                                     in_dir, 
                                     out_dir, 
                                     1,
                                     driller=driller_path,
                                     dictionary=dictionary,
                                     eof_termination=eof_exit)
        procs.append(driller)

    else:
        l.warning("only one AFL instance was chosen to be spun up, driller will never be invoked")

    # only spins up an AFL instances if afl_count > 1
    for n in range(2, afl_count):
        slave = start_afl_instance(afl_path, 
                                binary_path,
                                in_dir,
                                out_dir,
                                n,
                                dictionary=dictionary,
                                eof_termination=eof_exit)

        procs.append(slave)

### BACKEND HANDLERS

def clear_redis(identifier):
    redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)

    # delete all the catalogue entries
    redis_inst.delete("%s-catalogue" % identifier)

    # delete all the traced entries
    redis_inst.delete("%s-traced" % identifier)

    # delete all the crash-found entry
    redis_inst.delete("%s-crash-found" % identifier)

def report_crash_found(identifier):
    redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)

    # add True as a member
    redis_inst.sadd(identifier + "-crash-found", True)

def listen(queue_dir, channel):
    l.debug("subscring to redis channel %s" % channel)
    l.debug("new inputs will be placed into %s" % queue_dir)

    try:
        os.makedirs(queue_dir)
    except OSError:
        l.warning("could not create output directory '%s'" % queue_dir)

    redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)
    p = redis_inst.pubsub()

    p.subscribe(channel)

    input_cnt = 0

    for msg in p.listen():
        if msg['type'] == 'message':
            real_msg = pickle.loads(msg['data'])
            out_filename = "driller-%d-%x-%x" % real_msg['meta']
            l.debug("dumping new input to %s" % out_filename)
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

### STATS

def show_afl_stats(sync_dir):
    global start_time

    stats = {}
    checktime = time.time()

    driller_inputs = 0
    # collect stats into dictionary
    for fuzzer_dir in os.listdir(sync_dir):
        stat_path = os.path.join(sync_dir, fuzzer_dir, "fuzzer_stats")
        if os.path.isfile(stat_path):
            stats[fuzzer_dir] = {}

            with open(stat_path, "rb") as f:
                stat_blob = f.read()
                stat_lines = stat_blob.split("\n")[:-1]
                for stat in stat_lines:
                    key, val = stat.split(":")
                    stats[fuzzer_dir][key.strip()] = val

        else: # could be driller
            if fuzzer_dir == "driller":
                drilled_inputs = len(os.listdir(os.path.join(sync_dir, fuzzer_dir, "queue")))

    pending_total = 0
    pending_favs  = 0
    execs_done = 0
    total_time = 0
    alive_cnt = 0
    crashes = 0
    for fuzzer in stats:
        # is the fuzzer alive
        fuzz_pid = int(stats[fuzzer]['fuzzer_pid'])
        try:
            os.kill(fuzz_pid, 0)
            alive_cnt += 1
        except OSError:
            continue

        time_running   = checktime - int(stats[fuzzer]['start_time'])
        total_time    += time_running
        pending_total += int(stats[fuzzer]['pending_total'])
        pending_favs  += int(stats[fuzzer]['pending_favs'])
        execs_done    += int(stats[fuzzer]['execs_done'])
        crashes       += int(stats[fuzzer]['unique_crashes'])

    return crashes

def start(binary_path, in_dir, out_dir, afl_count, work_dir=None, timeout=None):
    global procs
    global start_time

    base = os.path.dirname(__file__)

    work_dir      = "." if work_dir is None else work_dir
    # start time
    start_time    = time.time()
    # the path to AFL capable of calling driller
    afl_path      = os.path.join(base, "driller-afl-fuzz")
    # the AFL build path for afl-qemu-trace-*
    afl_path_var  = os.path.join(base, "build", "afl")
    # path to the drill script
    driller_path  = os.path.join(base, "drill.py")
    # driller-qemu
    qemu_dir      = os.path.join(base, config.QEMU_DIR)
    # redis channel id
    channel_id    = os.path.basename(binary_path)
    # afl dictionary
    dict_file     = os.path.join(work_dir, "%s.dict" % channel_id)

    l.debug("afl_path: %s" % afl_path)
    l.debug("driller_path: %s" % driller_path)
    l.debug("AFL_PATH_ENV: %s" % afl_path_var)
    l.debug("channel_id: %s" % channel_id) 

    # test to see if the binary is so bad it crashes on our test case
    crash_found = crash_test(qemu_dir, binary_path)

    # clear redis database
    clear_redis(channel_id)

    # look for a dictionary, if one doesn't exist create it with angr
    if not os.path.isfile(dict_file):
        try:
            l.debug("creating a dictionary of string references found in the binary")
            if not create_dict(binary_path, dict_file):
                l.warning("failed to create dictionary for binary \"%s\"", channel_id)
                dict_file = None
        except Exception as e:
            l.error("encountered %r exception when creating fuzzer dict for \"%s\"", e, channel_id)
            dict_file = None

    # set environment variable for the AFL_PATH
    os.environ['AFL_PATH'] = afl_path_var

    # spin up the AFL guys
    start_afl(afl_path, binary_path, in_dir, out_dir, afl_count, 
            dictionary=dict_file, driller_path=driller_path, eof_exit=False)

    # spin up the redis listener
    procs.append(start_redis_listener(channel_id, out_dir))

    # setup signal handler
    signal.signal(signal.SIGINT, terminate)

    time_left = True
    while not crash_found and time_left:
        time.sleep(config.CRASH_CHECK_INTERVAL)
        crash_found = bool(show_afl_stats(out_dir))
        time_left = (int(time.time()) - start_time) < config.FUZZ_TIMEOUT
        l.debug("[%s] crash found? %r" % (channel_id, crash_found))

    if not time_left:
        l.warning("timed out for binary \"%s\"", channel_id)
    if crash_found:
        l.info("found crash for binary \"%s\"", channel_id)

    report_crash_found(channel_id)
    kill_procs()

    return crash_found

def main():
    l.setLevel("INFO")

    parser = argparse.ArgumentParser(description="Driller")

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

    return start(binary_path, in_dir, out_dir, afl_count)

if __name__ == "__main__":
    sys.exit(main())
