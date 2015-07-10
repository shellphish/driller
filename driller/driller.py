import logging
import logconfig

l = logging.getLogger("driller")
l.setLevel("INFO")

import angr
import simuvex
import archinfo

import tempfile
import os
import multiprocessing
import time
import subprocess
import functools

# shared objects for multiprocessing

# lock for the catalogue file
catalogue_lock = multiprocessing.RLock()

# shared value for the output counter
output_cnt     = multiprocessing.Value("L", 0, lock=True)

class DrillerEnvironmentError(Exception):
    pass

class DrillerMisfollowError(Exception):
    pass

class DrillerConservativeStartup(Exception):
    pass

class Driller(object):
    '''
    Driller object, can invoke many processes to trace inputs and drill into new state transitions.
    '''

    TRACED_FILE    = "traced"
    CATALOGUE_FILE = "driller_catalogue"
    STATS_FILE     = "driller_stats"
    ALIVE_FILE     = "alive"
    SOLO_INTERVAL  = 60 * 30             # 30 minutes

    def __init__(self, binary, in_dir, out_dir, fuzz_bitmap_file, qemu_dir, proc_cnt=1,
                 sync_dir=None):
        '''
        :param binary: the binary to be traced
        :param in_dir: directory of inputs to feed to the binary
        :param out_dir: directory to place drilled outputs
        :param fuzz_bitmap_file: AFL's bitmap of state transitions as a file
        :param qemu_dir: path to driller qemu binaries
        :param proc_cnt: number of driller workers to invoke during tracing
        '''

        self.binary           = binary
        self.in_dir           = in_dir
        self.out_dir          = out_dir
        self.fuzz_bitmap_file = fuzz_bitmap_file
        self.qemu_dir         = qemu_dir
        self.proc_cnt         = proc_cnt
        self.parallel         = False if sync_dir is None else True
        self.sync_dir         = sync_dir

        if self.parallel:
            self._conservative_startup_check()

        # the output directoy is organized into a dock, a queue, and stat files

        # the dock is used for all the outputs created during a single driller invokation
        # we use a directory to make it easy to transfer new inputs to AFL
        self.dock_dir         = os.path.join(self.out_dir, "dock")

        # the queue contains every input create over multiple driller invokations, named 'queue'
        # to make integration with AFL easy
        self.queue_dir        = os.path.join(self.out_dir, "queue")

        # traced catalogue file to prevent tracing inputs which have already been traced
        # organized as a list of filenames which have been traced seperated by line
        self.traced_file      = os.path.join(self.out_dir, self.TRACED_FILE)

        # set of the files which have already been traced
        self.traced           = set()

        # drilled catalogue file to prevent producing redundant inputs
        # organized as a list of length,start_addr,end_addr tuples seperated by line
        self.catalogue_file   = os.path.join(self.out_dir, self.CATALOGUE_FILE)

        # some variables to speed up usage of the catalogue
        self.catalogue_cache  = set()

        # previous size of the the catalogue cache
        self.catalogue_size   = 0

        # stat file containing book keeping information
        # colon delimited key value pairs seperated by line
        self.stats_file       = os.path.join(self.out_dir, self.STATS_FILE)

        # list of input files
        self.inputs           = [ ]

        # dictionary of input files and basic block traces
        self.traces           = { }
        
        # set of encountered basic block transition
        self.encountered      = set()

        # start time, set by drill method
        self.start_time       = time.time()

        l.info("drilling started on %s" % time.ctime(self.start_time))

        # setup directories for the driller and perform sanity checks on the directory structure here
        if not self._sane():
            l.error("environment or parameters are unfit for a driller run")
            raise DrillerEnvironmentError

        # setup the output directory and special files for tracking
        if not self._setup():
            l.error("unable to setup environment for driller")
            raise DrillerEnvironmentError

        self._accumulate_traces()

        l.debug("%d traces" % len(self.traces))
        l.debug("%d state transitions" % len(self.encountered))


### ENVIRONMENT CHECKS AND OBJECT SETUP
         
    def _sane(self):
        ''' 
        make sure the environment will allow us to run without any hitches
        '''
        ret = True

        # does the input directory exist? 
        if not os.path.isdir(self.in_dir):
            l.error("input directory does not exist")
            ret = False

        # does the fuzzer's bitmap exist and is it a file?
        if not os.path.isfile(self.fuzz_bitmap_file):
            l.error("fuzzer bitmap provided does not exist or is not a file")
            ret = False

        # some process count was actually specified?
        if self.proc_cnt < 1:
            l.error("need to specify 1 or more processes to drill")
            ret = False

        # warning if we specify more processes than CPU cores
        if self.proc_cnt > multiprocessing.cpu_count():
            l.warning("be careful specifying more driller processes than you have CPU cores")

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
        global output_cnt
    
        # make the dock directory, or clean it
        try:
            os.makedirs(self.dock_dir)
        except OSError:
            if not os.path.isdir(self.dock_dir):
                l.error("cannot make dock directory \"%s\"" % self.dock_dir)
                return False
            else:
                # if the dock directory exists we clean the contents of it dock
                # preventing AFL from picking up inputs which it tested in a previous run
                l.info("dock directory \"%s\" already exists, removing contents" % self.dock_dir)
                for f in os.listdir(self.dock_dir):
                    fpath = os.path.join(self.dock_dir, f)
                    os.remove(fpath)

        # make the queue directory if it doesn't already exist
        try:
            os.makedirs(self.queue_dir)
        except OSError:
            if not os.path.isdir(self.queue_dir):
                l.error("cannot make queue directory \"%s\"" % self.queue_dir)
                return False
         
        # populate the list of input files
        self.inputs = [i for i in os.listdir(self.in_dir) if not i.startswith(".")]

        # open the fuzz_bitmap and populate an instance variable with it and it's length
        self.fuzz_bitmap = open(self.fuzz_bitmap_file).read()
        self.fuzz_bitmap_size = len(self.fuzz_bitmap)

        l.debug("fuzz_bitmap of size %d bytes loaded" % self.fuzz_bitmap_size)

        # create the stat file
        output_cnt.value = 0
        try:
            stat_blob = open(self.stats_file).read()

            # need to make sure we keep the count the same
            for line in stat_blob.split("\n"):
                line = line.strip()
                key, value = line.split(":") 
                if key == "count":
                    output_cnt.value = int(value)
                    break

        except IOError:
            pass

        # now create a new, updated driller_stats_file
        with open(self.stats_file, "w") as f:
            f.write("count:%d\n" % output_cnt.value)
            f.write("start:%d\n" % self.start_time)

        try:
            with open(self.catalogue_file) as f:
                self.catalogue_size = len(f.read())
        except IOError:
            # touch catalogue file
            with open(self.catalogue_file, "a"):
                os.utime(self.catalogue_file, None)

        # update the catalogue cache
        self._cache_update()

        try:
            with open(self.traced_file, "r") as f:
                self.traced = set(f.read().split("\n"))
        except IOError:
            # touch traced file
            with open(self.traced_file, "a"):
                os.utime(self.traced_file, None)

        # create the alive file for our dumb method of conservative startup
        f = open(os.path.join(self.out_dir, self.ALIVE_FILE), "w")
        f.close()

        # cleanse self.inputs of any files in traced
        self.inputs = filter(lambda i: i not in self.traced, self.inputs)

        return True

    def _accumulate_traces(self):
        l.info("accumulating %d traces with QEMU" % len(self.inputs))

        qemu_bin = "driller-qemu-%s" % self._arch_string()
        qemu_path = os.path.join(self.qemu_dir, qemu_bin)

        # quickly validate that the qemu binary exists
        if not os.access(qemu_path, os.X_OK):
            l.error("QEMU binary for target's arch either does not exist or is not executable")
            raise DrillerEnvironmentError

        for input_file in self.inputs:
            # generate a logfile for the trace, will be thrown away shortly
            fd, logfile = tempfile.mkstemp(prefix="driller-trace-", dir="/dev/shm/")

            # args to Popen
            args = [qemu_path, "-d", "exec", "-D", logfile, self.binary]

            ifp = open(os.path.join(self.in_dir, input_file))
            ofp = open("/dev/null", "w")

            # run QEMU with the input file as stdin
            p = subprocess.Popen(args, stdin=ifp, stdout=ofp)
            p.wait()

            ifp.close()
            ofp.close()

            trace = open(logfile).read()
            os.remove(logfile)

            tracelines = trace.split("\n")
            tracelines = filter(lambda v: v.startswith("Trace"), tracelines)
            addrs = map(lambda v: int(v.split("[")[1].split("]")[0], 16), tracelines)

            # make an association with the basic blocks traversed and the input file which does it
            self.traces[input_file] = addrs

            # now look through traces for unique state transitions
            for i, addr in enumerate(addrs):
                if (i + 1) < len(addrs):
                    transition = (addr, addrs[i+1])
                    self.encountered.add(transition)
                else:
                    break

    def _arch_string(self):

        # temporary angr project for getting loader options
        p = angr.Project(self.binary)
        ld_arch = p.ld.main_bin.arch
        ld_type = p.ld.main_bin.filetype

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

    def _conservative_startup_check(self):
        '''
        dumb method of checking if any driller processes have been invoked recently
        '''
        checktime = int(time.time())

        startup_times = [ ]
        # check all the slave directories
        for directory in os.listdir(self.sync_dir):
            stats_file = os.path.join(self.sync_dir, directory, self.STATS_FILE)
            if os.path.exists(stats_file):
                stat_blob = open(stats_file).read()
                for line in stat_blob.split("\n"):
                    key, value = line.split(":")
                    if key == "start":
                        startup_time = int(value)
                        break

                alive_file = os.path.join(self.sync_dir, directory, self.ALIVE_FILE)
                alive = os.path.exists(alive_file)

                if alive:
                    startup_times.append(startup_time)

        if len(startup_times) > 0:
            if (checktime - max(startup_times)) < self.SOLO_INTERVAL:
                raise DrillerConservativeStartup


### DRILLING

    def drill(self):
        '''
        perform the drilling, finding more code coverage based off our existing input base.
        '''

        # if it's just a single process we don't mess with the multiprocessing module
        if self.proc_cnt == 1:
            for input_file in self.inputs:
                self._drill_input(input_file)

        else:
            l.info("spinning up %d processes to get the job done" % self.proc_cnt)

            p = multiprocessing.Pool(self.proc_cnt)
            p.map(self._drill_input, self.inputs)

        # update traced
        with open(self.traced_file, "a") as f:
            f.write('\n'.join(self.inputs) + '\n')

        os.remove(os.path.join(self.out_dir, self.ALIVE_FILE))

    def _drill_input(self, input_file):
        '''
        symbolically step down a path, choosing branches based off a dynamic trace we took earlier.
        if there's any branches (or state transitions really) which weren't taken by any of the inputs
        we concretize an input to reach those branches (or state transitions really).

        :param input_file: input file which produces the path to drill to into
        '''

        # grab the dynamic basic block trace
        bb_trace = self.traces[input_file]

        l.debug("drilling into \"%s\"" % input_file)
        l.debug("input \"%s\" has a basic block trace of %d addresses" % (input_file, len(bb_trace)))

        project = angr.Project(self.binary)
        # apply special simprocedures
        self._set_simprocedures(project)

        parent_path = project.path_generator.entry_point(add_options={simuvex.s_options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY})

        # TODO: detect unconstrained paths
        trace_group = project.path_group(immutable=False, paths=[parent_path])

        # used for following the dynamic trace
        bb_cnt = 0

        # used for finding the right index in the fuzz_bitmap
        prev_loc = 0

        # initialize the missed stash in the trace_group path group
        trace_group.missed = [ ]

        while len(trace_group.active) > 0:

            bb_cnt, next_move = self._windup_to_branch(trace_group, bb_trace, bb_cnt)

            # move the transition which the dynamic trace didn't encounter to the 'missed' stash
            trace_group.stash_not_addr(next_move, to_stash='missed')

            # make sure we actually have one active path at this point
            # in the case which we have no paths but a next_move, that's trouble
            if next_move is not None and len(trace_group.active) < 1:
                l.error("taking the branch at 0x%x is unsatisfiable to angr" % next_move)
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

                    if not hit and transition not in self.encountered:
                        if path.state.satisfiable():
                            # we writeout the new input as soon as possible to allow other AFL slaves
                            # to work with it
                            self._writeout(bb_trace[bb_cnt-1], path)
                        else:
                            l.info("couldn't dump input for %x -> %x" % transition)

            trace_group.drop(stash='missed')
            
    def _windup_to_branch(self, path_group, bb_trace, bb_idx):
        '''
        step through a path_group until multiple branches can be taken, we return the our new position 
        in the basic block trace and the branch which the dynamic trace took.

        :param path_group: a mutable angr path_group 
        :param bb_trace: a list of basic block address taken by the dynamic trace
        :param bb_idx: the current index into the bb_trace
        :return: a tuple of the new basic block index and the next move taken by the dynamic trace
        '''

        while len(path_group.active) == 1:
            current = path_group.active[0]

            if len(bb_trace[bb_idx:]) == 0 and len(current.successors) == 0:
                pass # angr makes one step after the _terminate call, qemu doesn't
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

    def _cache_update(self):
        '''
        update our local catalogue cache with the value of the catalogue on disk.
        assumes that the catalogue lock has been acquired
        '''

        catalogue_blob = open(self.catalogue_file).read()
        self.catalogue_size = len(catalogue_blob)
        for entry in catalogue_blob.split("\n")[:-1]:
            l, paddr, naddr = map(lambda x: int(x, 16), entry.split(","))
            self.catalogue_cache.add((l, paddr, naddr))

    def _catalogue_update(self, entry):
        '''
        update the cache on disk with the entry

        :param entry: entry to update the catalogue_file with
        '''

        new_entry = "%x,%x,%x\n" % entry

        with open(self.catalogue_file, "a") as f:
            f.write(new_entry)

        self.catalogue_size += len(new_entry)
        self.catalogue_cache.add(entry)

    def _in_catalogue(self, length, prev_addr, next_addr):
        '''
        check if a generated input has already been generated earlier during the run or by another
        thread.

        :param length: length of the input
        :param prev_addr: the source address in the state transition
        :param next_addr: the destination address in the state transition
        :return: boolean describing whether or not the input generated is redundant
        '''
        global catalogue_lock

        if (length, prev_addr, next_addr) in self.catalogue_cache:
            return True

        # if it's not in the cache a cache update is required, so grab the lock
        catalogue_lock.acquire()

        # have new entries been added to the cache?
        if self.catalogue_size != os.path.getsize(self.catalogue_file):
            self._cache_update()
            if (length, prev_addr, next_addr) in self.catalogue_cache:
                catalogue_lock.release()
                return True

        # we need to update the cache
        self._catalogue_update((length, prev_addr, next_addr))

        catalogue_lock.release()
        return False

    def _writeout(self, prev_addr, path):
        global output_cnt

        generated = path.state.posix.dumps(0)

        # checks here to see if the generation is worth writing to disk
        # if we generate too many inputs which are not really different we'll seriously slow down AFL
        if self._in_catalogue(len(generated), prev_addr, path.addr):
            return

        l.info("dumping input for %x -> %x" % transition)

        out_filename = "driller-%d-%x-%x" % (len(generated), prev_addr, path.addr)
        afl_name = "id:%06d,src:%s" % (output_cnt.value, out_filename)
        out_file = os.path.join(os.path.abspath(self.queue_dir), afl_name)

        with open(out_file, "w") as ofp:
            ofp.write(generated)

        # symlink the file to the dock
        dock_link = os.path.join(self.dock_dir, out_filename)

        # if this raises an exception most likely some race condition is occuring
        os.symlink(out_file, dock_link)

        # increment the link
        with output_cnt.get_lock():
            output_cnt.value += 1

            # update the stats file
            with open(self.stats_file, "w") as f:
                blob = "count:%d\nstart:%d\n" % (output_cnt.value, self.start_time)
                f.write(blob)
