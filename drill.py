#!/usr/bin/env pypy

'''
Frontend for driller, AFL invokes this script when it's having trouble making any progress.
'''

import logging
import logconfig

# silence these loggers
logging.getLogger().setLevel("CRITICAL")

l = logging.getLogger("driller.drill")
l.setLevel("INFO")

import driller
import driller.tasks
import driller.config

import os
import sys
import time
import hashlib
import argparse

import redis

def get_fuzzer_id(input_data_path):
    # get the fuzzer id
    abs_path = os.path.abspath(input_data_path)
    if "sync/" not in abs_path or "id:" not in abs_path:
        l.warning("path %s, cant find fuzzer id", abs_path)
        return "None"
    fuzzer_name = abs_path.split("sync/")[-1].split("/")[0]
    input_id = abs_path.split("id:")[-1].split(",")[0]
    return fuzzer_name + ",src:" + input_id

def input_filter(input_dir, inputs):

    # dumb hack to the fuzzer's directory
    fuzzer_dir = os.path.dirname(input_dir[:-1])

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

def main(argv):
    parser = argparse.ArgumentParser(description="Increase AFL's code coverage")
    
    parser.add_argument("-b", dest="binary", 
                        type=str, 
                        metavar="<binary>", 
                        help="binary executable",
                        required=True)

    parser.add_argument("-i", 
                        dest="in_dir", 
                        type=str, 
                        metavar="<in_dir>", 
                        help="input directory", 
                        required=True)

    parser.add_argument("-f", 
                        dest="bitmap_file",
                        type=str, 
                        metavar="<bitmap_file>",
                        help="AFL's fuzz bitmap file",
                        required=True)

    args = parser.parse_args(argv)
    
    binary      = args.binary
    in_dir      = args.in_dir
    bitmap_file = args.bitmap_file

    # use the basename, the worker will be on a different system
    binary = os.path.basename(binary)

    # anything in AFL's input directory which starts with a '.' is book keeping
    inputs = filter(lambda d: not d.startswith('.'), os.listdir(in_dir))

    # let's filter out input which we've already sent
    inputs = input_filter(in_dir, inputs)
    l.info("[%s] Drilling job requested at %s with %d inputs sent", binary, time.ctime(), len(inputs))

    # put the bitmap into redis
    fuzz_bitmap = open(bitmap_file, 'rb').read()
    bitmap_hash = hashlib.sha256(fuzz_bitmap).hexdigest()
    redis_inst = redis.Redis(host=driller.config.REDIS_HOST,
                             port=driller.config.REDIS_PORT,
                             db=driller.config.REDIS_DB)
    redis_inst.hset(binary + '-bitmaps', bitmap_hash, fuzz_bitmap)

    for input_file in inputs:
        input_data_path = os.path.join(in_dir, input_file)
        input_data = open(input_data_path, 'rb').read()
        tag = get_fuzzer_id(input_data_path)

        driller.tasks.drill.delay(binary, input_data, bitmap_hash, tag)

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
