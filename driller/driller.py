import os
import time
import signal
import hashlib
import resource
import cPickle as pickle
import logging

import angr
import tracer
from . import config


l = logging.getLogger("driller.driller")


class Driller(object):
    """
    Driller object, symbolically follows an input looking for new state transitions.
    """

    def __init__(self, binary, input_str, fuzz_bitmap=None, tag=None, redis=None, hooks=None, argv=None):
        """
        :param binary     : The binary to be traced.
        :param input_str  : Input string to feed to the binary.
        :param fuzz_bitmap: AFL's bitmap of state transitions (defaults to empty).
        :param redis      : redis.Redis instance for coordinating multiple Driller instances.
        :param hooks      : Dictionary of addresses to simprocedures.
        :param argv       : Optionally specify argv params (i,e,: ['./calc', 'parm1']),
                            defaults to binary name with no params.
        """

        self.binary      = binary

        # Redis channel identifier.
        self.identifier  = os.path.basename(binary)
        self.input       = input_str
        self.fuzz_bitmap = fuzz_bitmap
        self.tag         = tag
        self.redis       = redis
        self.argv = argv or [binary]

        self.base = os.path.join(os.path.dirname(__file__), "..")

        # The simprocedures.
        self._hooks = {} if hooks is None else hooks

        # The driller core, which is now an exploration technique in angr.
        self._core = None

        # Start time, set by drill method.
        self.start_time = time.time()

        # Set of all the generated inputs.
        self._generated = set()

        # Set the memory limit specified in the config.
        if config.MEM_LIMIT is not None:
            resource.setrlimit(resource.RLIMIT_AS, (config.MEM_LIMIT, config.MEM_LIMIT))

        l.debug("[%s] drilling started on %s.", self.identifier, time.ctime(self.start_time))

### DRILLING

    def drill(self):
        """
        Perform the drilling, finding more code coverage based off our existing input base.
        """

        # Don't re-trace the same input.
        if self.redis and self.redis.sismember(self.identifier + '-traced', self.input):
            return -1

        # Write out debug info if desired.
        if l.level == logging.DEBUG and config.DEBUG_DIR:
            self._write_debug_info()
        elif l.level == logging.DEBUG and not config.DEBUG_DIR:
            l.warning("Debug directory is not set. Will not log fuzzing bitmap.")

        # Update traced.
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

        # Set up alarm for timeouts.
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
        c = angr.exploration_techniques.CrashMonitor(trace=r.trace, crash_mode=r.crash_mode, crash_addr=r.crash_addr)
        self._core = angr.exploration_techniques.DrillerCore(trace=r.trace)

        simgr.use_technique(c)
        simgr.use_technique(t)
        simgr.use_technique(angr.exploration_techniques.Oppologist())
        simgr.use_technique(self._core)

        self._set_concretizations(simgr.one_active)

        l.debug("Drilling into %r.", self.input)
        l.debug("Input is %r.", self.input)

        simgr.run()

        for state in simgr.diverted:
            l.debug("Found a diverted state, explorting to some extent.")
            w = self._writeout(state.history.bbl_addrs[-1], state)
            if w is not None:
                yield w
            for i in self._symbolic_explorer_stub(state):
                yield i

### EXPLORER

    def _symbolic_explorer_stub(self, state):
        # Create a new simulation manager and step it forward up to 1024
        # accumulated active states or steps.
        steps = 0
        accumulated = 1

        p = angr.Project(self.binary)
        simgr = p.factory.simgr(path, immutable=False, hierarchy=False)

        l.debug("[%s] started symbolic exploration at %s.", self.identifier, time.ctime())

        while len(simgr.active) and accumulated < 1024:
            simgr.step()
            steps += 1

            # Dump all inputs.
            accumulated = steps * (len(simgr.active) + len(simgr.deadended))

        l.debug("[%s] stopped symbolic exploration at %s.", self.identifier, time.ctime())

        for dumpable in simgr.deadended:
            try:
                if dumpable.satisfiable():
                    w = self._writeout(dumpable.history.bbl_addrs[-1], dumpable)
                    if w is not None:
                        yield w

            # If the state we're trying to dump wasn't actually satisfiable.
            except IndexError:
                pass

### UTILS

    @staticmethod
    def _set_concretizations(state):
        flag_vars = set()
        for b in state.cgc.flag_bytes:
            flag_vars.update(b.variables)

        state.unicorn.always_concretize.update(flag_vars)

        # Let's put conservative thresholds for now.
        state.unicorn.concretization_threshold_memory = 50000
        state.unicorn.concretization_threshold_registers = 50000

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

        # No redis means no coordination, so no catalogue.
        else:
            return False

    def _add_to_catalogue(self, length, prev_addr, next_addr):
        if self.redis:
            key = '%x,%x,%x\n' % (length, prev_addr, next_addr)
            self.redis.sadd(self.identifier + '-catalogue', key)
        # No redis = no catalogue.

    def _writeout(self, prev_addr, state):
        t_pos = state.posix.files[0].pos
        state.posix.files[0].seek(0)

        # Read up to the length.
        generated = state.posix.read_from(0, t_pos)
        generated = state.se.eval(generated, cast_to=str)
        state.posix.files[0].seek(t_pos)

        key = (len(generated), prev_addr, state.addr)

        # Checks here to see if the generation is worth writing to disk.
        # If we generate too many inputs which are not really different we'll seriously slow down AFL.
        if self._in_catalogue(*key):
            self._core.encounters.remove((prev_addr, state.addr))
            return

        else:
            self._add_to_catalogue(*key)

        l.debug("[%s] dumping input for %#x -> %#x.", self.identifier, prev_addr, state.addr)

        self._generated.add((key, generated))

        if self.redis:
            # Publish it out in real-time so that inputs get there immediately.
            channel = self.identifier + '-generated'

            self.redis.publish(channel, pickle.dumps({'meta': key, 'data': generated, "tag": self.tag}))

        else:
            l.debug("Generated: %s!", generated.encode('hex'))

        return (key, generated)

    def _write_debug_info(self):
        m = hashlib.md5()
        m.update(self.input)
        f_name = os.path.join(config.DEBUG_DIR, self.identifier + '_' + m.hexdigest() + '.py')

        with open(f_name, 'w+') as f:
            l.debug("Debug log written to %s.", f_name)
            f.write("binary = %r\n" % self.binary
                    + "started = '%s'\n" % time.ctime(self.start_time)
                    + "input = %r\n" % self.input
                    + "fuzz_bitmap = %r" % self.fuzz_bitmap)
