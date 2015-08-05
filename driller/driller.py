import logging

l = logging.getLogger("driller.Driller")

import tracer

import cle
import angr
import simuvex
import archinfo

import os
import time
import signal
import struct
import resource
import functools
import tempfile
import subprocess
import multiprocessing
import cPickle as pickle
from itertools import islice, izip

from simprocedures import cgc_simprocedures

import config

class DrillerEnvironmentError(Exception):
    pass

class DrillerMisfollowError(Exception):
    pass

class Driller(object):
    '''
    Driller object, symbolically follows an input looking for new state transitions
    '''

    def __init__(self, binary, input, fuzz_bitmap, redis=None):
        '''
        :param binary: the binary to be traced
        :param input: input string to feed to the binary
        :param fuzz_bitmap: AFL's bitmap of state transitions
        :param redis: redis.Redis instance for coordinating multiple Driller instances
        '''

        self.binary      = binary
        # redis channel identifier
        self.identifier  = os.path.basename(binary)
        self.input       = input
        self.fuzz_bitmap = fuzz_bitmap
        self.redis       = redis

        self.base = os.path.join(os.path.dirname(__file__), "..")

        self.qemu_dir = os.path.join(self.base, "driller-qemu")

        # set of encountered basic block transition
        self._encounters = set()

        # start time, set by drill method
        self.start_time       = time.time()

        # set of all the generated inputs
        self._generated       = set()

        # set the memory limit specified in the config
        if config.MEM_LIMIT is not None:
            resource.setrlimit(resource.RLIMIT_AS, (config.MEM_LIMIT, config.MEM_LIMIT))

        l.info("[%s] drilling started on %s", self.identifier, time.ctime(self.start_time))

        self.fuzz_bitmap_size = len(self.fuzz_bitmap)

        # setup directories for the driller and perform sanity checks on the directory structure here
        if not self._sane():
            l.error("[%s] environment or parameters are unfit for a driller run", self.identifier)
            raise DrillerEnvironmentError

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

        # set up alarm for timeouts
        if config.DRILL_TIMEOUT is not None:
            signal.alarm(config.DRILL_TIMEOUT)

        self._drill_input()

        return len(self._generated)

    def _drill_input(self):
        '''
        symbolically step down a path with a tracer, trying to concretize inputs for unencountered
        state transitions.
        '''

        # initialize the tracer
        t = tracer.Tracer(self.binary, self.input, cgc_simprocedures)

        # update encounters with known state transitions
        self._encounters.update(izip(t.trace, islice(t.trace, 1, None)))

        l.debug("drilling into %r" % self.input)
        l.debug("input is %r", self.input)

        # used for finding the right index in the fuzz_bitmap
        prev_loc = 0

        branches = t.next_branch()
        while len(branches.active) > 0:

            # check here to see if a crash has been found
            if self.redis and self.redis.sismember(self.identifier + "-finished", True):
                return

            # mimic AFL's indexing scheme
            if len(branches.missed) > 0:
                prev_loc = t.trace[t.bb_cnt-1] # a bit ugly
                prev_loc = (prev_loc >> 4) ^ (prev_loc << 8)
                prev_loc &= self.fuzz_bitmap_size - 1
                prev_loc = prev_loc >> 1
                for path in branches.missed:
                    cur_loc = path.addr
                    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8)
                    cur_loc &= self.fuzz_bitmap_size - 1

                    hit = bool(ord(self.fuzz_bitmap[cur_loc ^ prev_loc]) ^ 0xff)

                    transition = (t.trace[t.bb_cnt-1], path.addr)

                    l.debug("found %x -> %x transition" % transition)

                    if not hit and not self._has_encountered(transition):
                        t.remove_preconstraints(path)
                        if path.state.satisfiable():
                            # we writeout the new input as soon as possible to allow other AFL slaves
                            # to work with it
                            l.debug("found new cool thing!")
                            self._writeout(t.trace[t.bb_cnt-1], path)
                        else:
                            l.debug("couldn't dump input for %x -> %x" % transition)

            branches = t.next_branch()
            
### UTILS

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

        l.info("[%s] dumping input for %x -> %x", self.identifier, prev_addr, path.addr)

        self._generated.add((key, generated))

        if self.redis:
            # publish it out in real-time so that inputs get there immediately
            channel = self.identifier + '-generated'

            self.redis.publish(channel, pickle.dumps({'meta': key, 'data': generated}))
