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

l = logging.getLogger("fuzz")
l.setLevel("INFO")

# global list of processes so we can kill them on SIGINT
procs = [ ] 

start_time = 0

### EXIT HANDLERS

def terminate(signal, frame):
    map(lambda p: p.terminate(), procs)
    sys.exit(0)

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
                s = hexescape(string)
                f.write("driller_%d=\"%s\"\n" % (i, s))

        return True

    return False

### BEHAVIOR TESTING
def terminates_on_eof(qemu_dir, binary):
    l.info("attempting to detect if the binary doesn't terminate on EOF")

    # detect the binary type
    b = angr.Project(binary)
    ld_arch = b.loader.main_bin.arch
    ld_type = b.loader.main_bin.filetype

    if ld_type == "cgc":
        arch = "cgc"

    elif ld_type == "elf":
        if ld_arch == archinfo.arch_amd64.ArchAMD64:
            arch = "x86_64"
        if ld_arch == archinfo.arch_x86.ArchX86:
            arch = "i386"

    else:
        l.error("binary is of an unsupported architecture")
        raise NotImplementedError

    qemu_path = os.path.join(qemu_dir, "driller-qemu-%s" % arch)
    if not os.access(qemu_path, os.X_OK):
        l.error("either qemu does not exist in config.QEMU_DIR or it is not executable")
        return True

    # create a dumb test input 
    fd, tinput = tempfile.mkstemp()
    os.close(fd)

    with open(tinput, 'wb') as f:
        f.write("fuzz")

    with open(tinput, 'rb') as i:
        with open('/dev/null', 'w') as o:
            args = [qemu_path, binary]
            p = subprocess.Popen(args, stdin=i, stdout=o)

            time.sleep(2) # generously give the binary two seconds to terminate

            if p.poll() is None: # it doesn't seem to terminate on EOF
                p.terminate()
                return False
            
    # good, it terminates on EOF, no monkey business
    return True

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
    l.info("subscring to redis channel %s" % channel)
    l.info("new inputs will be placed into %s" % queue_dir)

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

            stat_blob = open(stat_path, "rb").read()
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

    m, s = divmod(checktime - start_time, 60)
    h, m = divmod(m, 60)
    print "  Run time           : %d:%02d:%02d" % (h, m, s)
    print "  Fuzzers Alive      : %d alive" % alive_cnt
    print "  Pending paths      : %d faves, %d total" % (pending_favs, pending_total)
    print "  Pending per fuzzer : %d faves, %d total" % (pending_favs / alive_cnt, pending_total / alive_cnt)
    print "  Cumulative speed   : %d execs/sec" % int((execs_done * alive_cnt) / total_time)
    print "  Drilled inputs     : %d inputs" % drilled_inputs

    cstr = "%d" % crashes
    if crashes > 0:
        cstr = termcolor.colored(cstr, "red", attrs=["bold"])

    print "  Crashes            : %s crashes" % cstr
    print
    print "=" * 40

    return crashes

def start(binary_path, in_dir, out_dir, afl_count):
    global procs
    global start_time

    base = os.path.dirname(__file__)

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
    dict_file     = "%s.dict" % channel_id

    l.debug("afl_path: %s" % afl_path)
    l.debug("driller_path: %s" % driller_path)
    l.debug("AFL_PATH_ENV: %s" % afl_path_var)
    l.debug("channel_id: %s" % channel_id) 

    # clear redis database
    clear_redis(channel_id)

    # look for a dictionary, if one doesn't exist create it with angr
    if not os.path.isfile(dict_file):
        l.info("creating a dictionary of string references found in the binary")
        if not create_dict(binary_path, dict_file):
            l.warning("failed to create dictionary, this can really impede on AFL's progress")
            dict_file = None

    # set environment variable for the AFL_PATH
    os.environ['AFL_PATH'] = afl_path_var

    eof_exit = False
    # test if the binary terminates on EOF
    if not terminates_on_eof(qemu_dir, binary_path):
        l.warning("binary doesn't terminate on EOF! attempting to use hack to fix this")
        eof_exit = True

    # spin up the AFL guys
    start_afl(afl_path, binary_path, in_dir, out_dir, afl_count, 
            dictionary=dict_file, driller_path=driller_path, eof_exit=eof_exit)

    # spin up the redis listener
    procs.append(start_redis_listener(channel_id, out_dir))

    # setup signal handler
    signal.signal(signal.SIGINT, terminate)

    crash_found = False
    while not crash_found:
        time.sleep(config.CRASH_CHECK_INTERVAL)
        crash_found = bool(show_afl_stats(out_dir))

    report_crash_found(channel_id)
    terminate()

    return 0

def main():

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
