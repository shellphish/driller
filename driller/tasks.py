import os
import time
import pcap
import redis
import fuzzer
import logging
import hashlib
import driller.config as config
from celery import Celery
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

@app.task
def fuzz(binary):

    l.info("beginning to fuzz \"%s\"", binary)

    binary_path = os.path.join(config.BINARY_DIR, binary)

    seeds = ["fuzz"]
    # look for a pcap
    pcap_path = os.path.join(config.BINARY_DIR, "%s.pcap" % binary)
    if os.path.isfile(pcap_path):
        seeds += pcap.process(pcap_path)
    else:
        l.warning("unable to find pcap file, will seed fuzzer with the default")

    fzr = fuzzer.Fuzzer(binary_path, config.FUZZER_WORK_DIR, config.FUZZER_INSTANCES, seeds)

    early_crash = False
    try:
        fzr.start()

        # start the fuzzer and poll for a crash or timeout
        while not fzr.found_crash() and not fzr.timed_out():
            # check to see if driller should be invoked
            if not int(fzr.stats['fuzzer-1']['pending_favs']) > 0:
                bitmap_data = open(os.path.join(fzr.out_dir, "fuzzer-1", "bitmap"), "rb").read()
                bitmap_hash = hashlib.sha256(bitmap_data).hexdigest()
                in_dir = os.path.join(fzr.out_dir, "fuzzer-1", "queue")
                # submit a driller job for each item in the queue
                for input_file in os.listdir(in_dir):
                    input_data = open(input_file, "rb").read()
                    input_data_path = os.path.join(in_dir, input_file)
                    drill.delay(fzr.binary_id, input_data, bitmap_hash, get_fuzzer_id(input_data_path))
            time.sleep(config.CRASH_CHECK_INTERVAL)

        # make sure to kill the fuzzers when we're done
        fzr.kill()

    except fuzzer.EarlyCrash:
        l.info("binary crashed on dummy testcase, moving on...")
        early_crash = True

    if early_crash or fzr.found_crash():
        l.info("found crash for \"%s\"", binary)
        redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)
        redis_inst.publish("crashes", binary)

    if fzr.timed_out():
        l.info("timed out while fuzzing \"%s\"", binary)

    # stop any drilling taking place on the binary
    fzr.end_drilling()

    return fzr.found_crash() or early_crash
