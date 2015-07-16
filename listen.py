import argparse
import cPickle as pickle
import os

import redis

def main(argv):
    parser = argparse.ArgumentParser(description="Listen for generated inputs from Redis")

    parser.add_argument("-o",
                        dest="out_dir",
                        type=str,
                        metavar="<out_dir>",
                        help="output directory",
                        required=True)

    parser.add_argument("binary",
                        type=str,
                        help="binary executable")

    args = parser.parse_args(argv)

    queue_dir = os.path.join(args.out_dir, "queue")
    channel = args.binary + '-generated'

    if not os.path.isdir(queue_dir):
        os.makedirs(queue_dir)

    redis_inst = redis.Redis(host='localhost', port=6379, db=1)
    p = redis_inst.pubsub()

    p.subscribe(channel)

    input_cnt = 0

    for msg in p.listen():
        if msg['type'] == 'message':
            real_msg = pickle.loads(msg['data'])
            out_filename = "driller-%d-%x-%x" % real_msg['meta']
            afl_name = "id:%06d,src:%s" % (input_cnt, out_filename)
            out_file = os.path.join(queue_dir, afl_name)

            with open(out_file, 'wb') as ofp:
                ofp.write(real_msg['data'])

            input_cnt += 1

    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv[1:]))
