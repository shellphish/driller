#!/usr/bin/env python

import angr
import driller.config as config

import os
import time
import redis
import string
import tempfile
import subprocess
import multiprocessing
import cPickle as pickle

import logging

l = logging.getLogger("driller.Fuzzer")

class EarlyCrash(Exception):
    pass

def hexescape(s):
    '''
    perform hex escaping on a raw string s
    '''

    out = [ ]
    acceptable = string.letters + string.digits + " ."
    for c in s:
        if c not in acceptable:
            out.append("\\x%02x" % ord(c))
        else:
            out.append(c)

    return ''.join(out)


def listen(queue_dir, channel):
    '''
    listen for new inputs produced by driller

    :param queue_dir: directory to places new inputs
    :param channel: redis channel on which the new inputs will be arriving
    '''

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

class Fuzzer(object):
    ''' Fuzzer object, spins up a fuzzing job on a binary '''

    def __init__(self, binary_path, work_dir, afl_count):
        '''
        :param binary_path: path to the binary to fuzz
        :param work_dir: the work directory which contains fuzzing jobs, our job directory will go here
        :param afl_count: number of AFL jobs total to spin up for the binary
        '''

        self.binary_path = binary_path
        self.work_dir    = work_dir
        self.afl_count   = afl_count

        # binary id
        self.binary_id = os.path.basename(binary_path)

        self.job_dir  = os.path.join(self.work_dir, self.binary_id)
        self.in_dir   = os.path.join(self.job_dir, "input")
        self.out_dir  = os.path.join(self.job_dir, "sync")

        # base of the driller project
        self.base = os.path.join(os.path.dirname(__file__), "..")

        self.start_time    = int(time.time())
        # the path to AFL capable of calling driller
        self.afl_path      = os.path.join(self.base, "driller-afl-fuzz")
        # the AFL build path for afl-qemu-trace-*
        self.afl_path_var  = os.path.join(self.base, "build", "afl")
        # path to the drill script
        self.driller_path  = os.path.join(self.base, "drill.py")
        # driller-qemu
        self.qemu_dir      = os.path.join(self.base, config.QEMU_DIR)
        # afl dictionary
        self.dictionary    = os.path.join(self.job_dir, "%s.dict" % self.binary_id)
        # processes spun up
        self.procs         = [ ] 
        # start the fuzzer ids at 0
        self.fuzz_id       = 0
        # set when fuzzers are running
        self.alive         = False

        l.debug("self.start_time: %r" % self.start_time)
        l.debug("self.afl_path: %s" % self.afl_path)
        l.debug("self.afl_path_var: %s" % self.afl_path_var)
        l.debug("self.driller_path: %s" % self.driller_path)
        l.debug("self.qemu_dir: %s" % self.qemu_dir)
        l.debug("self.binary_id: %s" % self.binary_id) 
        l.debug("self.work_dir: %s" % self.work_dir) 
        l.debug("self.dictionary: %s" % self.dictionary) 

        # clear redis database
        self._clear_redis()

        # create the work directory and input directory
        try:
            os.makedirs(self.in_dir)
        except OSError:
            l.warning("unable to create in_dir \"%s\"", self.in_dir)

        # populate the input directory
        with open(os.path.join(self.in_dir, "fuzz"), "wb") as f:
            f.write("fuzz")

        # look for a dictionary, if one doesn't exist create it with angr
        if not os.path.isfile(self.dictionary):
            try:
                l.debug("creating a dictionary of string references found in the binary")
                if not self._create_dict():
                    l.warning("failed to create dictionary for binary \"%s\"", self.binary_id)
                    self.dictionary = None
            except Exception as e:
                l.error("encountered %r exception when creating fuzzer dict for \"%s\"", e, self.binary_id)
                self.dictionary = None

        # set environment variable for the AFL_PATH
        os.environ['AFL_PATH'] = self.afl_path_var

    ### EXPOSED
    def start(self):
        ''' 
        start fuzzing 
        '''

        # test to see if the binary is so bad it crashes on our test case
        if self._crash_test():
            raise EarlyCrash

        # spin up the redis listener
        self.procs.append(self._driller_listener())

        # spin up the AFL workers
        self._start_afl()

        self.alive = True

    def kill(self):
        map(lambda p: p.terminate(), self.procs)
        self.alive = False

    def stats(self):

        # collect stats into dictionary
        stats = {}
        for fuzzer_dir in os.listdir(self.out_dir):
            stat_path = os.path.join(self.out_dir, fuzzer_dir, "fuzzer_stats")
            if os.path.isfile(stat_path):
                stats[fuzzer_dir] = {}

                with open(stat_path, "rb") as f:
                    stat_blob = f.read()
                    stat_lines = stat_blob.split("\n")[:-1]
                    for stat in stat_lines:
                        key, val = stat.split(":")
                        stats[fuzzer_dir][key.strip()] = val

        return stats

    def found_crash(self):

        stats = self.stats()

        for job in stats:
            try:
                if int(stats[job]['unique_crashes']) > 0:
                    return True
            except KeyError:
                pass

        return False

    def timed_out(self):

        checktime = int(time.time())

        return (checktime - self.start_time) > config.FUZZ_TIMEOUT

    def add_fuzzer(self):

        self.procs.append(self._start_afl_instance())

    def add_fuzzers(self, n):
        for _ in range(n):
            self.add_fuzzer()

    ### DICTIONARY CREATION

    def _create_dict(self):
        b = angr.Project(self.binary_path)
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
            with open(self.dictionary, 'wb') as f:
                for i, string in enumerate(strings):
                    # AFL has a limit of 128 bytes per dictionary entries
                    if len(string) <= 128:
                        s = hexescape(string)
                        f.write("driller_%d=\"%s\"\n" % (i, s))

            return True

        return False

    ### BEHAVIOR TESTING

    def _crash_test(self):

        args = [os.path.join(self.qemu_dir, "driller-qemu-cgc"), self.binary_path]

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

        os.remove(jfile)
        return ret

    ### AFL SPAWNERS

    def _start_afl_instance(self, memory="8G", driller=None):

        args = [self.afl_path]

        args += ["-i", self.in_dir]
        args += ["-o", self.out_dir]
        args += ["-m", memory]
        args += ["-Q"]
        if self.fuzz_id == 0:
            args += ["-M", "fuzzer-master"]
            outfile = "fuzzer-master.log"
        else:
            args += ["-S", "fuzzer-%d" % self.fuzz_id]
            outfile = "fuzzer-%d.log" % self.fuzz_id

        if self.dictionary is not None:
            args += ["-x", self.dictionary]

        if driller:
            args += ["-D", self.driller_path]

        args += ["--", self.binary_path]

        l.debug("execing: %s > %s" % (' '.join(args), outfile))

        outfile = os.path.join(self.job_dir, outfile)
        fp = open(outfile, "w")

        # increment the fuzzer ID
        self.fuzz_id += 1

        return subprocess.Popen(args, stdout=fp)

    def _start_afl(self):
        '''
        start up a number of AFL instances to begin fuzzing
        '''

        # spin up the master AFL instance
        master = self._start_afl_instance() # the master fuzzer
        self.procs.append(master)

        if self.afl_count > 1:
            driller = self._start_afl_instance(driller=True)
            self.procs.append(driller)

        else:
            l.warning("only one AFL instance was chosen to be spun up, driller will never be invoked")

        # only spins up an AFL instances if afl_count > 1
        for n in range(2, self.afl_count):
            slave = self._start_afl_instance()
            self.procs.append(slave)

    ### BACKEND HANDLERS

    def _driller_listener(self):
        driller_queue_dir = os.path.join(self.out_dir, "driller", "queue")
        channel = "%s-generated" % self.binary_id

        # ugly Popen hack to get around multiprocessing

        args = [os.path.join(self.base, "listen.py"), driller_queue_dir, channel]
        return subprocess.Popen(args)

    def _clear_redis(self):
        redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)

        # delete all the catalogue entries
        redis_inst.delete("%s-catalogue" % self.binary_id)

        # delete all the traced entries
        redis_inst.delete("%s-traced" % self.binary_id)

        # delete all the crash-found entry
        redis_inst.delete("%s-crash-found" % self.binary_id)

    def report_crash_found(identifier):
        redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)

        # add True as a member
        redis_inst.sadd(identifier + "-crash-found", True)
