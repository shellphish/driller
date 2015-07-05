import angr
import simuvex
import archinfo

import tempfile
import os
import multiprocessing
import time
import subprocess

import logging

l = logging.getLogger("driller")
l.setLevel("DEBUG")

class DrillerEnvironmentError(Exception):
    pass

class DrillerMisfollowError(Exception):
    pass

class Driller(object):
    '''
    Driller object, can invoke many processes to trace inputs and drill into new state transitions.
    '''

    TRACED_CATALOGUE = ".traced"

    def __init__(self, binary, in_dir, out_dir, fuzz_bitmap_file, qemu_dir, proc_cnt=1,
                 parallel=False, sync_dir=None):
        '''
        :param binary: the binary to be traced
        :param in_dir: directory of inputs to feed to the binary
        :param out_dir: directory to place drilled outputs
        :param fuzz_bitmap_file: AFL's bitmap of state transitions as a file
        :param proc_cnt: number of driller workers to invoke during tracing
        :param parallel: boolean describing whether driller is being invoked by a parallel AFL run
        :param sync_dir: the sync directory to use for driller_outputs
        :param qemu_path: path to driller qemu binaries
        '''

        self.binary           = binary
        self.in_dir           = in_dir
        self.out_dir          = out_dir
        self.fuzz_bitmap_file = fuzz_bitmap_file
        self.qemu_dir         = qemu_dir
        self.proc_cnt         = proc_cnt
        self.parallel         = parallel
        self.sync_dir         = sync_dir

        # list of input files
        self.inputs           = [ ]

        # dictionary of input files and basic block traces
        self.traces           = { }
        
        # set of encountered basic block transition
        self.encountered      = set()

        # setup directories for the driller and perform sanity checks on the directory structure here
        if not self._sane():
            l.error("environment or parameters are unfit for a driller run")
            return

        # setup the output directory and special files for tracking
        if not self._setup():
            l.error("unable to setup environment for driller")
            return

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

        # if parallel is turned on we need to check more stuff
        if self.parallel:
             
            # was the sync_dir specified and does it exist?
            if self.sync_dir is None:
                l.error("with parallel mode turned on, you must specify a sync directory")
                ret = False

        return ret

    def _setup(self):
        '''
        prepare driller for running
        '''
    
        # make the output directory, or clean it 
        try:
            os.makedirs(self.out_dir)
        except OSError:
            if not os.path.isdir(self.out_dir):
                l.error("cannot make output directory \"%s\"" % self.out_dir)
                return False
            else:
                l.info("output directory \"%s\" already exists, removing contents" % self.out_dir)
                for f in os.listdir(self.out_dir):
                    fpath = os.path.join(self.out_dir, f)
                    if f != self.TRACED_CATALOGUE:
                        os.remove(fpath)

         
        # populate the list of input files
        self.inputs = [i for i in os.listdir(self.in_dir) if not i.startswith(".")]

        # open the fuzz_bitmap and populate an instance variable with it and it's length
        self.fuzz_bitmap = open(self.fuzz_bitmap_file).read()
        self.fuzz_bitmap_size = len(self.fuzz_bitmap)

        l.debug("fuzz_bitmap of size %d bytes loaded" % self.fuzz_bitmap_size)

        # if driller has been invoked by a parallel AFL run, there's more work to do
        if self.parallel:

            # first we prepare the driller sync directory so other AFL instances can sync with 
            # driller outputs as they are produced
            try:
                os.makedirs(self.sync_dir)
            except OSError:
                if not os.path.isdir(self.sync_dir):
                    l.error("cannot make driller sync directory \"%s\"" % self.sync_dir)
                    return False

            # we introduce three new variables for keeping track of the sync directory
            # a driller_stats_file, a driller_catalogue_file, and a driller_sync_queue

            # the driller stats file contains how many new inputs we've created and when we last 
            # started up
            self.driller_stats_file = os.path.join(self.sync_dir, "driller_stats")

            # the driller catalogue file contains a list of unique state transitions we've generated
            # inputs for 
            self.driller_catalogue_file = os.path.join(self.sync_dir, "driller_catalogue")

            # the driller sync queue is where are new inputs are placed, it must be a named correctly
            # for AFL instances to find it
            self.driller_sync_queue = os.path.join(self.sync_dir, "queue")

            # create the sync queue if it doesn't exist
            try:
                os.makedirs(self.driller_sync_queue)
            except OSError:
                if not os.path.isdir(self.driller_sync_queue):
                    l.error("cannot make driller sync queue \"%s\"" % self.driller_sync_queue)
            
            # create the stat file
            driller_cnt = 0
            try:
                stat_blob = open(self.driller_stats_file).read()

                # need to make sure we keep the count the same
                for line in stat_blob.split("\n"):
                    line = line.strip()
                    key, value = line.split(":") 
                    if key == "count":
                        driller_cnt = value
                        break

            except IOError:
                pass

            # now create a new, updated driller_stats_file
            with open(self.driller_stats_file, "w") as f:
                f.write("count:%d\n" % int(driller_cnt))
                f.write("start:%d\n" % time.time())

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

    def _drill_input(self, input_file):
        '''
        symbolically step down a path, choosing branches based off a dynamic trace we took earlier.
        if there's any branches (or state transitions really) which weren't taken by any of the inputs
        we concretize an input to reach those branches (or state transitions really).

        :param input_file: input file which produces the path to drill to into
        '''

        # grab the dynamic basic block trace
        bb_trace = self.traces[input_file]

        l.info("drilling into \"%s\"" % input_file)
        l.info("input \"%s\" has a basic block trace of %d addresses" % (input_file, len(bb_trace)))

        project = angr.Project(self.binary)
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
                prev_loc = bb_trace[bb_cnt]
                prev_loc = (prev_loc >> 4) ^ (prev_loc << 8)
                prev_loc &= self.fuzz_bitmap_size - 1
                prev_loc = prev_loc >> 1
                for path in trace_group.stashes['missed']:
                    cur_loc = path.addr
                    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8)
                    cur_loc &= self.fuzz_bitmap_size - 1

                    hit = bool(ord(self.fuzz_bitmap[cur_loc ^ prev_loc]) ^ 0xff)

                    transition = (bb_trace[bb_cnt], path.addr)
                    if not hit and transition not in self.encountered:
                        if path.state.satisfiable:
                            l.info("dumping input for %x -> %x" % transition)
                            #self._writeout(path)

            trace_group.drop(stash='missed')
            
            bb_cnt += 1

    def _windup_to_branch(self, path_group, bb_trace, bb_idx):
        '''
        step through a path_group until multiple branches can be taken, we return the our new position 
        in the basic block trace and the branch which the dynamic trace took.

        :param path_group: a mutable angr path_group 
        :param bb_trace: a list of basic block address taken by the dynamic trace
        :param bb_idx: the current index into the bb_trace
        :return: a tuple of the new basic block index and the next move taken by the dynamic trace
        '''

        previous = bb_trace[bb_idx]
        while len(path_group.active) == 1:
            current = path_group.active[0]

            # we don't need these, free them to save memory
            current.trim_history()
            current.state.downsize()

            previous = current.addr
            path_group.step()

        # this occurs when a path deadends, no need to keep tracing it
        if len(path_group.active) == 0 and len(path_group.deadended) > 0:
            return (0, None)

        while bb_trace[bb_idx] != previous:
            bb_idx += 1

        return (bb_idx, bb_trace[bb_idx+1])
