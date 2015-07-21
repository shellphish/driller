import logging
import logconfig

l = logging.getLogger("driller.Driller")
l.setLevel("INFO")

import angr
import archinfo
import simuvex

import cPickle as pickle
import functools
from itertools import islice, izip
import multiprocessing
import os
import subprocess
import tempfile
import time

class DrillerEnvironmentError(Exception):
    pass

class DrillerMisfollowError(Exception):
    pass

class Driller(object):
    '''
    Driller object, symbolically follows an input looking for new state transitions
    '''

    def __init__(self, binary, input, fuzz_bitmap, qemu_dir, redis=None, exit_on_eof=False):
        '''
        :param binary: the binary to be traced
        :param input: input string to feed to the binary
        :param fuzz_bitmap: AFL's bitmap of state transitions
        :param qemu_dir: path to driller qemu binaries
        :param redis: redis.Redis instance for coordinating multiple Driller instances
        :param exit_on_eof: whether QEMU should exit if EOF is received, used for tracing binaries
                            which don't exit themselves
        '''

        self.binary      = binary
        # redis channel identifier
        self.identifier  = os.path.basename(binary)
        self.input       = input
        self.fuzz_bitmap = fuzz_bitmap
        self.qemu_dir    = qemu_dir
        self.redis       = redis
        self.exit_on_eof = exit_on_eof

        # set of the files which have already been traced
        self.traced           = set()

        # set of encountered basic block transition
        self._encounters = set()

        # start time, set by drill method
        self.start_time       = time.time()

        # set of all the generated inputs
        self._generated       = set()

        l.info("drilling started on %s" % time.ctime(self.start_time))

        self.fuzz_bitmap_size = len(self.fuzz_bitmap)

        # setup directories for the driller and perform sanity checks on the directory structure here
        if not self._sane():
            l.error("environment or parameters are unfit for a driller run")
            raise DrillerEnvironmentError

        # basic block trace, initialized in .drill
        self.trace = None


### ENVIRONMENT CHECKS AND OBJECT SETUP
         
    def _sane(self):
        ''' 
        make sure the environment will allow us to run without any hitches
        '''
        ret = True

        # check permissions on the binary to ensure it's executable
        if not os.access(self.binary, os.X_OK):
            l.error("passed binary file is not executable")
            ret = False

        # check if the qemu dir is set up correctly
        if not os.path.isdir(self.qemu_dir):
            l.error("the QEMU directory \"%s\" either does not exist or is not a directory" % self.qemu_dir)
            ret = False

        return ret

    def _setup(self):
        '''
        prepare driller for running
        '''

        # save fuzz_bitmap's size
        self.fuzz_bitmap_size = len(self.fuzz_bitmap)

        l.debug("fuzz_bitmap of size %d bytes loaded" % self.fuzz_bitmap_size)

        return True

    def _trace(self):
        qemu_bin = "driller-qemu-%s" % self._arch_string()
        qemu_path = os.path.join(self.qemu_dir, qemu_bin)

        # quickly validate that the qemu binary exists
        if not os.access(qemu_path, os.X_OK):
            l.error("QEMU binary for target's arch either does not exist or is not executable")
            raise DrillerEnvironmentError

        # generate a logfile for the trace, will be thrown away shortly
        logfd, logfile = tempfile.mkstemp(prefix="driller-trace-", dir="/dev/shm/")
        os.close(logfd)

        # args to Popen
        args = [qemu_path]
        if self.exit_on_eof:
            args += ["-eof-exit"]
        args += ["-d", "exec", "-D", logfile, self.binary]

        with open('/dev/null', 'wb') as devnull:
            # run QEMU with the input file as stdin
            p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=devnull)
            p.communicate(self.input)
            p.wait()

        trace = open(logfile, 'rb').read()
        os.remove(logfile)

        addrs = [int(v.split('[')[1].split(']')[0], 16)
                 for v in trace.split('\n')
                 if v.startswith('Trace')]

        # update encounters with known state transitions
        self._encounters.update(izip(addrs, islice(addrs, 1, None)))

        return addrs

    def _arch_string(self):

        # temporary angr project for getting loader options
        p = angr.Project(self.binary)
        ld_arch = p.loader.main_bin.arch
        ld_type = p.loader.main_bin.filetype

        # what's the binary's format?
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

        return arch


### DRILLING

    def drill(self):
        '''
        perform the drilling, finding more code coverage based off our existing input base.
        '''

        if self.redis and self.redis.sismember(self.identifier + '-traced', self.input):
            # don't re-trace the same input
            return 0

        # update traced
        if self.redis:
            self.redis.sadd(self.identifier + '-traced', self.input)

        self.trace = self._trace()

        self._drill_input()

        return len(self._generated)

    def _drill_input(self):
        '''
        symbolically step down a path, choosing branches based off a dynamic trace we took earlier.
        if there's any branches (or state transitions really) which weren't taken by any of the inputs
        we concretize an input to reach those branches (or state transitions really).
        '''

        # grab the dynamic basic block trace
        bb_trace = self.trace

        l.debug("drilling into %r" % self.input)
        l.debug("basic block trace consists of %d addresses" % len(bb_trace))

        project = angr.Project(self.binary)

        # apply special simprocedures
        self._set_simprocedures(project)

        l.debug("input is %r", self.input)

        parent_path = project.factory.entry_state(add_options={simuvex.s_options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY})

        # TODO: detect unconstrained paths
        trace_group = project.factory.path_group(parent_path, immutable=False, save_unconstrained=True)

        # used for following the dynamic trace
        bb_cnt = 0

        # used for finding the right index in the fuzz_bitmap
        prev_loc = 0

        # initialize the missed stash in the trace_group path group
        trace_group.missed = [ ]

        while len(trace_group.active) > 0:
            bb_cnt, next_move = self._windup_to_branch(trace_group, bb_trace, bb_cnt)

            if len(trace_group.stashes['unconstrained']):
                l.info("%d unconstrained paths spotted!" % len(trace_group.stashes['unconstrained']))

            # check here to see if a crash has been found
            if self.redis and self.redis.sismember(self.identifier + "-crash-found", True):
                return

            # move the transition which the dynamic trace didn't encounter to the 'missed' stash
            trace_group.stash_not_addr(next_move, to_stash='missed')

            # make sure we actually have one active path at this point
            # in the case which we have no paths but a next_move, that's trouble
            if next_move is not None and len(trace_group.active) < 1:
                l.error("taking the branch at %#x is unsatisfiable to angr" % next_move)
                l.error("input was %r" % self.input)
                raise DrillerMisfollowError

            # mimic AFL's indexing scheme
            if len(trace_group.stashes['missed']) > 0:
                prev_loc = bb_trace[bb_cnt-1]
                prev_loc = (prev_loc >> 4) ^ (prev_loc << 8)
                prev_loc &= self.fuzz_bitmap_size - 1
                prev_loc = prev_loc >> 1
                for path in trace_group.stashes['missed']:
                    cur_loc = path.addr
                    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8)
                    cur_loc &= self.fuzz_bitmap_size - 1

                    hit = bool(ord(self.fuzz_bitmap[cur_loc ^ prev_loc]) ^ 0xff)

                    transition = (bb_trace[bb_cnt-1], path.addr)

                    l.debug("found %x -> %x transition" % transition)

                    if not hit and not self._has_encountered(transition):
                        if path.state.satisfiable():
                            # we writeout the new input as soon as possible to allow other AFL slaves
                            # to work with it
                            l.debug("found new cool thing!")
                            self._writeout(bb_trace[bb_cnt-1], path)
                        else:
                            l.debug("couldn't dump input for %x -> %x" % transition)

            trace_group.drop(stash='missed')
            
    def _windup_to_branch(self, path_group, bb_trace, bb_idx):
        '''
        step through a path_group until multiple branches can be taken, we return the our new position 
        in the basic block trace and the branch which the dynamic trace took.

        :param path_group: a mutable angr path_group 
        :param bb_trace: a list of basic block address taken by the dynamic trace
        :param bb_idx: the current index into bb_trace
        :return: a tuple of the new basic block index and the next move taken by the dynamic trace
        '''

        while len(path_group.active) == 1:
            current = path_group.active[0]

            # l.info("current at %#x", current.addr)

            if len(bb_trace[bb_idx:]) == 0:
                return (bb_idx, None)
            elif current.addr == bb_trace[bb_idx]:
                bb_idx += 1  # expected behaviour, the trace matches the angr basic block
            elif current.addr == previous:
                pass # angr steps through the same basic block trace when a syscall occurs
            else:
                l.error("The qemu trace and the angr trace differ, this most likely suggests a bug")
                l.error("qemu [0x%x], angr [0x%x]" % (bb_trace[bb_idx], current.addr))
                raise DrillerMisfollowError

            # we don't need these, free them to save memory
            current.trim_history()
            current.state.downsize()

            previous = current.addr
            path_group.step()

        # this occurs when a path deadends, no need to keep tracing it
        if len(path_group.active) == 0 and len(path_group.deadended) > 0:
            return (0, None)

        return (bb_idx, bb_trace[bb_idx])

### UTILS

    def _set_simprocedures(self, project):
        from simprocedures import cgc_simprocedures

        # TODO: support more than CGC
        simprocs = cgc_simprocedures
        for symbol, procedure in simprocs:
            simuvex.SimProcedures['cgc'][symbol] = procedure

    def _has_encountered(self, transition):
        return transition in self._encounters

    def _in_catalogue(self, length, prev_addr, next_addr):
        '''
        check if a generated input has already been generated earlier during the run or by another
        thread.

        :param length: length of the input
        :param prev_addr: the source address in the state transition
        :param next_addr: the destination address in the state transition
        :return: boolean describing whether or not the input generated is redundant
        '''
        key = '%x,%x,%x\n' % (length, prev_addr, next_addr)

        if self.redis:
            return self.redis.sismember(self.identifier + '-catalogue', key)
        else:
            # no redis means no coordination, so no catalogue
            return False

    def _add_to_catalogue(self, length, prev_addr, next_addr):
        if self.redis:
            key = '%x,%x,%x\n' % (length, prev_addr, next_addr)
            self.redis.sadd(self.identifier + '-catalogue', key)
        # no redis = no catalogue

    def _writeout(self, prev_addr, path):
        generated = path.state.posix.dumps(0)
        key = (len(generated), prev_addr, path.addr)

        # checks here to see if the generation is worth writing to disk
        # if we generate too many inputs which are not really different we'll seriously slow down AFL
        if self._in_catalogue(*key):
            return
        else:
            self._encounters.add((prev_addr, path.addr))
            self._add_to_catalogue(*key)

        l.info("dumping input for %x -> %x" % (prev_addr, path.addr))

        self._generated.add((key, generated))

        if self.redis:
            # publish it out in real-time so that inputs get there immediately
            channel = self.identifier + '-generated'

            self.redis.publish(channel, pickle.dumps({'meta': key, 'data': generated}))
