import redis
from celery import Celery

from .Fuzzer import Fuzzer

import os
import time
import driller.config as config
import logging

l = logging.getLogger("fuzzer.tasks")

backend_url = "redis://%s:%d" % (config.REDIS_HOST, config.REDIS_PORT)
app = Celery('fuzzer', broker=config.BROKER_URL, backend=backend_url)

@app.task
def fuzz(binary):

    binary_path = os.path.join(config.BINARY_DIR, binary)
    fuzzer = Fuzzer(binary_path, "tests", config.FUZZER_INSTANCES)

    try:
        fuzzer.start()
    except Fuzzer.EarlyCrash:
        l.info("binary crashed on dummy testcase, moving on...")
        return 0

    # start the fuzzer and poll for a crash or timeout
    fuzzer.start()
    while not fuzzer.found_crash() and not fuzzer.timed_out():
        time.sleep(config.CRASH_CHECK_INTERVAL)

    # make sure to kill the fuzzers when we're done
    fuzzer.kill()

    return fuzzer.found_crash()
