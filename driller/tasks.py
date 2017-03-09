import os
import time
import pcap
import redis
import fuzzer
import logging
import hashlib
import subprocess
from celery import Celery
import config
from .driller import Driller

l = logging.getLogger("driller.tasks")

backend_url = "redis://%s:%d" % (config.REDIS_HOST, config.REDIS_PORT)
app = Celery('tasks', broker=config.BROKER_URL, backend=backend_url)
app.conf.CELERY_ROUTES = config.CELERY_ROUTES
app.conf['CELERY_ACKS_LATE'] = True
app.conf['CELERYD_PREFETCH_MULTIPLIER'] = 1

redis_pool = redis.ConnectionPool(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)

def get_fuzzer_id(input_data_path):
    # get the fuzzer id
    abs_path = os.path.abspath(input_data_path)
    if "sync/" not in abs_path or "id:" not in abs_path:
        l.warning("path %s, cant find fuzzer id", abs_path)
        return "None"
    fuzzer_name = abs_path.split("sync/")[-1].split("/")[0]
    input_id = abs_path.split("id:")[-1].split(",")[0]
    return fuzzer_name + ",src:" + input_id

@app.task
def drill(binary, input_data, bitmap_hash, tag):
    redis_inst = redis.Redis(connection_pool=redis_pool)
    fuzz_bitmap = redis_inst.hget(binary + '-bitmaps', bitmap_hash)

    binary_path = os.path.join(config.BINARY_DIR, binary)
    driller = Driller(binary_path, input_data, fuzz_bitmap, tag, redis=redis_inst)
    try:
        return driller.drill()
    except Exception as e:
        l.error("encountered %r exception when drilling into \"%s\"", e, binary)
        l.error("input was %r", input_data)

def input_filter(fuzzer_dir, inputs):

    traced_cache = os.path.join(fuzzer_dir, "traced")

    traced_inputs = set()
    if os.path.isfile(traced_cache):
        with open(traced_cache, 'rb') as f:
            traced_inputs = set(f.read().split('\n'))

    new_inputs = filter(lambda i: i not in traced_inputs, inputs)

    with open(traced_cache, 'ab') as f:
        for new_input in new_inputs:
            f.write("%s\n" % new_input)

    return new_inputs

def request_drilling(fzr):
    '''
    request a drilling job on a fuzzer object

    :param fzr: fuzzer object to request drilling on behalf of, this is needed to fine the input input queue
    :return: list of celery AsyncResults, we accumulate these so we can revoke them if need be
    '''

    d_jobs = [ ]

    bitmap_f = os.path.join(fzr.out_dir, "fuzzer-1", "fuzz_bitmap")
    bitmap_data = open(bitmap_f, "rb").read()
    bitmap_hash = hashlib.sha256(bitmap_data).hexdigest()

    redis_inst = redis.Redis(connection_pool=redis_pool)
    redis_inst.hset(fzr.binary_id + '-bitmaps', bitmap_hash, bitmap_data)

    in_dir = os.path.join(fzr.out_dir, "fuzzer-1", "queue")

    # ignore hidden files
    inputs = filter(lambda d: not d.startswith('.'), os.listdir(in_dir))

    # filter inputs which have already been sent to driller
    inputs = input_filter(os.path.join(fzr.out_dir, "fuzzer-1"), inputs)

    # submit a driller job for each item in the queue
    for input_file in inputs:
        input_data_path = os.path.join(in_dir, input_file)
        input_data = open(input_data_path, "rb").read()
        d_jobs.append(drill.delay(fzr.binary_id, input_data, bitmap_hash, get_fuzzer_id(input_data_path)))

    return d_jobs

def start_listener(fzr):
    '''
    start a listener for driller inputs
    '''

    driller_queue_dir = os.path.join(fzr.out_dir, "driller", "queue")
    channel = "%s-generated" % fzr.binary_id

    # find the bin directory listen.py will be installed in
    base = os.path.dirname(__file__)

    while not "bin" in os.listdir(base) and os.path.abspath(base) != "/":
        base = os.path.join(base, "..")

    if os.path.abspath(base) == "/":
        raise Exception("could not find driller listener install directory")

    args = [os.path.join(base, "bin", "driller", "listen.py"), driller_queue_dir, channel]
    p = subprocess.Popen(args)

    # add the proc to the fuzzer's list of processes
    fzr.procs.append(p)

def clean_redis(fzr):
    redis_inst = redis.Redis(connection_pool=redis_pool)

    # delete all catalogued inputs
    redis_inst.delete("%s-catalogue" % fzr.binary_id)

    # delete all the traced entries
    redis_inst.delete("%s-traced" % fzr.binary_id)

    # delete the finished entry
    redis_inst.delete("%s-finsihed" % fzr.binary_id)

    # delete the fuzz bitmaps
    redis_inst.delete("%s-bitmaps" % fzr.binary_id)

def _check_for_instrumented(binary):
    '''
    Check for an AFL instrumented version of this binary. Does the check by name
    and searches in BINARY_DIR/INSTRUMENTED_DIR found in config file.
    :param binary: name of binary
    :return: True for found instrumented binary, False otherwise
    '''
    if config.INSTRUMENTED_DIR is None:
        l.debug("There is no instrumented binary directory.")
        return False

    instrumented_path = os.path.join(config.BINARY_DIR, config.INSTRUMENTED_DIR)
    if os.path.isdir(instrumented_path):
        if binary in os.listdir(instrumented_path):
            l.info("Found instrumented binary for %s", binary)
            return True
        l.info("No instrumented binary found for %s", binary)
        return False

    l.warning("Instrumented path does not seem to exist:")
    l.warning("%r", instrumented_path)
    return False

@app.task
def fuzz(binary):

    l.info("beginning to fuzz \"%s\"", binary)

    instrumented_check = _check_for_instrumented(binary)

    fuzz_binary = binary
    if instrumented_check:
        fuzz_binary = os.path.join(config.INSTRUMENTED_DIR, binary)
        fuzz_binary_path = os.path.join(config.BINARY_DIR, fuzz_binary)

    seeds = ["fuzz"]

    # look for a pcap
    pcap_path = os.path.join(config.PCAP_DIR, "%s.pcap" % binary)
    if os.path.isfile(pcap_path):
        l.info("found pcap for binary %s", binary)
        seeds = pcap.process(pcap_path)
    else:
        l.warning("unable to find pcap file, will seed fuzzer with the default")

    if instrumented_check:
        qemu = False
    else:
        qemu = True
    # TODO enable dictionary creation, this may require fixing parts of the fuzzer module
    fzr = fuzzer.Fuzzer(fuzz_binary_path, config.FUZZER_WORK_DIR, config.FUZZER_INSTANCES,
                        seeds=seeds, qemu=qemu, create_dictionary=True)

    early_crash = False
    try:
        fzr.start()

        # start a listening for inputs produced by driller
        start_listener(fzr)

        # clean all stale redis data
        clean_redis(fzr)

        # list of 'driller request' each is a celery async result object
        driller_jobs = [ ]

        # start the fuzzer and poll for a crash, timeout, or driller assistance
        while not fzr.found_crash() and not fzr.timed_out():
            # check to see if driller should be invoked
            if 'fuzzer-1' in fzr.stats and 'pending_favs' in fzr.stats['fuzzer-1']:
                if not int(fzr.stats['fuzzer-1']['pending_favs']) > 0:
                    l.info("[%s] driller being requested!", binary)
                    driller_jobs.extend(request_drilling(fzr))

            time.sleep(config.CRASH_CHECK_INTERVAL)

        # make sure to kill the fuzzers when we're done
        fzr.kill()

    except fuzzer.EarlyCrash:
        l.info("binary crashed on dummy testcase, moving on...")
        early_crash = True

    # we found a crash!
    if early_crash or fzr.found_crash():
        l.info("found crash for \"%s\"", binary)

        # publish the crash
        redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)
        redis_inst.publish("crashes", binary)

        # revoke any driller jobs which are still working
        for job in driller_jobs:
            if job.status == 'PENDING':
                job.revoke(terminate=True)

    if fzr.timed_out():
        l.info("timed out while fuzzing \"%s\"", binary)

    # TODO end drilling jobs working on the binary

    return fzr.found_crash() or early_crash
