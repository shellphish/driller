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
    """
    Driller object, symbolically follows an input looking for new state transitions.
    """

    def __init__(self, binary, input, fuzz_bitmap=None, tag=None, redis=None, hooks=None, argv=None): #pylint:disable=redefined-builtin
        """
        :param binary     : The binary to be traced.
        :param input      : Input string to feed to the binary.
        :param fuzz_bitmap: AFL's bitmap of state transitions (defaults to empty).
        :param redis      : redis.Redis instance for coordinating multiple Driller instances.
        :param hooks      : Dictionary of addresses to simprocedures.
        :param argv       : Optionally specify argv params (i,e,: ['./calc', 'parm1']),
                            defaults to binary name with no params.
        """

        self.binary      = binary
        # redis channel identifier
        self.identifier  = os.path.basename(binary)
        self.input       = input
        self.fuzz_bitmap = fuzz_bitmap or "\xff"*65535
        self.tag         = tag
        self.redis       = redis
        self.argv = argv or [binary]

        self.base = os.path.join(os.path.dirname(__file__), "..")

        # the simprocedures
        self._hooks = {} if hooks is None else hooks

        self._core = None

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
        """
        Make sure the environment will allow us to run without any hitches.
        """
        ret = True

        # check permissions on the binary to ensure it's executable
        if not os.access(self.binary, os.X_OK):
            l.error("passed binary file is not executable")
            ret = False

        return ret

### DRILLING

    def drill(self):
        """
        Perform the drilling, finding more code coverage based off our existing input base.
        """

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
        """
        A generator interface to the actual drilling.
        """

        # set up alarm for timeouts
        if config.DRILL_TIMEOUT is not None:
            signal.alarm(config.DRILL_TIMEOUT)

        for i in self._drill_input():
            yield i

    def _drill_input(self):
        """
        Symbolically step down a path with a tracer, trying to concretize inputs for unencountered
        state transitions.
        """

        # initialize the tracer
        r = tracer.qemu_runner.QEMURunner(self.binary, self.input, argv=self.argv)
        p = angr.misc.tracer.make_tracer_project(binary=self.binary, hooks=self._hooks)
        s = p.factory.tracer_state(input_content=self.input, magic_content=r.magic)

        simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)

        t = angr.exploration_techniques.Tracer(trace=r.trace)
        d = angr.exploration_techniques.DrillerCore(trace=r.trace)
        c = angr.exploration_techniques.CrashMonitor(trace=r.trace, crash_mode=r.crash_mode, crash_addr=r.crash_addr)

        simgr.use_technique(c)
        simgr.use_technique(t)
        simgr.use_technique(angr.exploration_techniques.Oppologist())
        simgr.use_technique(d)

        self._set_concretizations(simgr.one_active)

        l.debug("drilling into %r", self.input)
        l.debug("input is %r", self.input)

        # used for finding the right index in the fuzz_bitmap
        prev_loc = 0

        simgr.run()

        for state in simgr.diverted:
            w = self._writeout(state.history.bbl_addrs[-1], state)
            if w is not None:
                yield w
            for i in self._symbolic_explorer_stub(state):
                yield i

### EXPLORER

    def _symbolic_explorer_stub(self, path):
        # create a new path group and step it forward up to 1024 accumulated active paths or steps

        steps = 0
        accumulated = 1

        p = angr.Project(self.binary)
        pg = p.factory.simgr(path, immutable=False, hierarchy=False)

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
                if dumpable.satisfiable():
                    w = self._writeout(dumpable.history.bbl_addrs[-1], dumpable)
                    if w is not None:
                        yield w
            except IndexError: # if the path we're trying to dump wasn't actually satisfiable
                pass

### UTILS

    @staticmethod
    def _set_concretizations(state):
        flag_vars = set()
        for b in state.cgc.flag_bytes:
            flag_vars.update(b.variables)
        state.unicorn.always_concretize.update(flag_vars)
        # let's put conservative thresholds for now
        state.unicorn.concretization_threshold_memory = 50000
        state.unicorn.concretization_threshold_registers = 50000

    @staticmethod
    def _has_false(path):
        # check if the path is unsat even if we remove preconstraints
        claripy_false = path.se.false
        if path.scratch.guard.cache_key == claripy_false.cache_key:
            return True

        for c in path.se.constraints:
            if c.cache_key == claripy_false.cache_key:
                return True
        return False

    def _in_catalogue(self, length, prev_addr, next_addr):
        """
        Check if a generated input has already been generated earlier during the run or by another
        thread.

        :param length   : Length of the input.
        :param prev_addr: The source address in the state transition.
        :param next_addr: The destination address in the state transition.

        :return: boolean describing whether or not the input generated is redundant.
        """
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
        t_pos = path.posix.files[0].pos
        path.posix.files[0].seek(0)
        # read up to the length
        generated = path.posix.read_from(0, t_pos)
        generated = path.se.eval(generated, cast_to=str)
        path.posix.files[0].seek(t_pos)

        key = (len(generated), prev_addr, path.addr)

        # checks here to see if the generation is worth writing to disk
        # if we generate too many inputs which are not really different we'll seriously slow down AFL
        if self._in_catalogue(*key):
            self._core.encounters.remove((prev_addr, path.addr))
            return
        else:
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
