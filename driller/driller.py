import angr
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

class Driller(object):
    '''
    Driller object, can invoke many processes to trace inputs and drill into new state transitions.
    '''

    TRACED_CATALOGUE = ".traced"

    def __init__(self, binary, in_dir, out_dir, fuzz_bitmap, qemu_dir, proc_cnt=1,
                 parallel=False, sync_dir=None):
        '''
        :param binary: the binary to be traced
        :param in_dir: directory of inputs to feed to the binary
        :param out_dir: directory to place drilled outputs
        :param fuzz_bitmap: AFL's bitmap of state transitions as a file
        :param proc_cnt: number of driller workers to invoke during tracing
        :param parallel: boolean describing whether driller is being invoked by a parallel AFL run
        :param sync_dir: the sync directory to use for driller_outputs
        :param qemu_path: path to driller qemu binaries
        '''

        self.binary           = binary
        self.in_dir           = in_dir
        self.out_dir          = out_dir
        self.fuzz_bitmap      = fuzz_bitmap
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

        self.project          = angr.Project(self.binary)

        self._accumulate_traces()

        l.debug("%d traces" % len(self.traces))
        l.debug("%d state transitions" % len(self.encountered))

         
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
        if not os.path.isfile(self.fuzz_bitmap):
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

        l.debug(self.inputs)

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

            l.debug(args)

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

        ld_arch = self.project.ld.main_bin.arch
        ld_type = self.project.ld.main_bin.filetype

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
