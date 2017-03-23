import logging

l = logging.getLogger("driller.Driller")

import tracer

import angr

import os
import time
import signal
import resource
import cPickle as pickle
from itertools import islice, izip
import hashlib

import config #pylint:disable=relative-import

class DrillerEnvironmentError(Exception):
    pass

class DrillerMisfollowError(Exception):
    pass

class Driller(object):
    '''
    Driller object, symbolically follows an input looking for new state transitions
    '''

    def __init__(self, binary, input, fuzz_bitmap = "\xff" * 65535, tag=None, redis=None, hooks=None, argv=None): #pylint:disable=redefined-builtin
        '''
        :param binary: the binary to be traced
        :param input: input string to feed to the binary
        :param fuzz_bitmap: AFL's bitmap of state transitions (defaults to empty)
        :param redis: redis.Redis instance for coordinating multiple Driller instances
        :param hooks: dictionary of addresses to simprocedures
        :param argv: Optionally specify argv params (i,e,: ['./calc', 'parm1'])
            defaults to binary name with no params.
        '''

        self.binary      = binary
        # redis channel identifier
        self.identifier  = os.path.basename(binary)
        self.input       = input
        self.fuzz_bitmap = fuzz_bitmap
        self.tag         = tag
        self.redis       = redis
        self.argv = argv or [binary]

        self.base = os.path.join(os.path.dirname(__file__), "..")

        # the simprocedures
        self._hooks = {} if hooks is None else hooks

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

        return ret

### DRILLING

    def drill(self):
        '''
        perform the drilling, finding more code coverage based off our existing input base.
        '''

        if self.redis and self.redis.sismember(self.identifier + '-traced', self.input):
            # don't re-trace the same input
            return -1

        # Write out debug info if desired
        if l.level == logging.DEBUG and config.DEBUG_DIR:
            self._write_debug_info()
        elif l.level == logging.DEBUG and not config.DEBUG_DIR:
            l.warning("Debug directory is not set. Will not log fuzzing bitmap.")

        # update traced
        if self.redis:
            self.redis.sadd(self.identifier + '-traced', self.input)

        list(self._drill_input())

        if self.redis:
            return len(self._generated)
        else:
            return self._generated

    def drill_generator(self):
        '''
        A generator interface to the actual drilling.
        '''

        # set up alarm for timeouts
        if config.DRILL_TIMEOUT is not None:
            signal.alarm(config.DRILL_TIMEOUT)

        for i in self._drill_input():
            yield i

    def _drill_input(self):
        '''
        symbolically step down a path with a tracer, trying to concretize inputs for unencountered
        state transitions.
        '''

        # initialize the tracer
        t = tracer.Tracer(self.binary, self.input, hooks=self._hooks, argv=self.argv)

        self._set_concretizations(t)
        self._set_simproc_limits(t)

        # update encounters with known state transitions
        self._encounters.update(izip(t.trace, islice(t.trace, 1, None)))

        l.debug("drilling into %r", self.input)
        l.debug("input is %r", self.input)

        # used for finding the right index in the fuzz_bitmap
        prev_loc = 0

        branches = t.next_branch()
        while len(branches.active) > 0 and t.bb_cnt < len(t.trace):

            # check here to see if a crash has been found
            if self.redis and self.redis.sismember(self.identifier + "-finished", True):
                return

            # mimic AFL's indexing scheme
            if len(branches.missed) > 0:
                prev_addr = branches.missed[0].addr_trace[-1] # a bit ugly
                prev_loc = prev_addr
                prev_loc = (prev_loc >> 4) ^ (prev_loc << 8)
                prev_loc &= self.fuzz_bitmap_size - 1
                prev_loc = prev_loc >> 1
                for path in branches.missed:
                    cur_loc = path.addr
                    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8)
                    cur_loc &= self.fuzz_bitmap_size - 1

                    hit = bool(ord(self.fuzz_bitmap[cur_loc ^ prev_loc]) ^ 0xff)

                    transition = (prev_addr, path.addr)

                    l.debug("found %x -> %x transition", transition[0], transition[1])

                    if not hit and not self._has_encountered(transition) and not self._has_false(path):
                        t.remove_preconstraints(path)

                        if path.state.satisfiable():
                            # a completely new state transitions, let's try to accelerate AFL
                            # by finding  a number of deeper inputs
                            l.info("found a completely new transition, exploring to some extent")
                            w = self._writeout(prev_addr, path)
                            if w is not None:
                                yield w
                            for i in self._symbolic_explorer_stub(path):
                                yield i
                        else:
                            l.debug("path to %#x was not satisfiable", transition[1])

                    else:
                        l.debug("%x -> %x has already been encountered", transition[0], transition[1])

            try:
                branches = t.next_branch()
            except IndexError:
                branches.active = [ ]

### EXPLORER
    def _symbolic_explorer_stub(self, path):
        # create a new path group and step it forward up to 1024 accumulated active paths or steps

        steps = 0
        accumulated = 1

        p = angr.Project(self.binary)
        pg = p.factory.path_group(path, immutable=False, hierarchy=False)

        l.info("[%s] started symbolic exploration at %s", self.identifier, time.ctime())

        while len(pg.active) and accumulated < 1024:
            pg.step()
            steps += 1

            # dump all inputs

            accumulated = steps * (len(pg.active) + len(pg.deadended))

        l.info("[%s] symbolic exploration stopped at %s", self.identifier, time.ctime())

        pg.stash(from_stash='deadended', to_stash='active')
        for dumpable in pg.active:
            try:
                if dumpable.state.satisfiable():
                    w = self._writeout(dumpable.addr_trace[-1], dumpable)
                    if w is not None:
                        yield w
            except IndexError: # if the path we're trying to dump wasn't actually satisfiable
                pass


### UTILS

    @staticmethod
    def _set_simproc_limits(t):
        state = t.path_group.one_active.state
        state.libc.max_str_len = 1000000
        state.libc.max_strtol_len = 10
        state.libc.max_memcpy_size = 0x100000
        state.libc.max_symbolic_bytes = 100
        state.libc.max_buffer_size = 0x100000

    @staticmethod
    def _set_concretizations(t):
        state = t.path_group.one_active.state
        flag_vars = set()
        for b in t.cgc_flag_bytes:
            flag_vars.update(b.variables)
        state.unicorn.always_concretize.update(flag_vars)
        # let's put conservative thresholds for now
        state.unicorn.concretization_threshold_memory = 50000
        state.unicorn.concretization_threshold_registers = 50000

    def _has_encountered(self, transition):
        return transition in self._encounters

    @staticmethod
    def _has_false(path):
        # check if the path is unsat even if we remove preconstraints
        claripy_false = path.state.se.false
        if path.state.scratch.guard.cache_key == claripy_false.cache_key:
            return True

        for c in path.state.se.constraints:
            if c.cache_key == claripy_false.cache_key:
                return True
        return False

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
        t_pos = path.state.posix.files[0].pos
        path.state.posix.files[0].seek(0)
        # read up to the length
        generated = path.state.posix.read_from(0, t_pos)
        generated = path.state.se.any_str(generated)
        path.state.posix.files[0].seek(t_pos)

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

            self.redis.publish(channel, pickle.dumps({'meta': key, 'data': generated, "tag": self.tag}))
        else:
            l.info("generated: %s", generated.encode('hex'))

        return (key, generated)

    def _write_debug_info(self):
        m = hashlib.md5()
        m.update(self.input)
        f_name = os.path.join(config.DEBUG_DIR,
                              self.identifier + '_' + m.hexdigest() + '.py')
        with open(f_name, 'w+') as f:
            l.debug("Wrote debug log to %s", f_name)
            f.write("binary = %r\n" % self.binary +
                    "started = '%s'\n" % time.ctime(self.start_time) +
                    "input = %r\n" % self.input +
                    "fuzz_bitmap = %r" % self.fuzz_bitmap)
