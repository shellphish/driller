### Redis Options
REDIS_HOST=None
REDIS_PORT=None
REDIS_DB=None

### Celery Options
BROKER_URL= None

CELERY_ROUTES = None

### Environment Options

# directory contain driller-qemu versions, relative to the directoy node.py is invoked in
QEMU_DIR=None

# directory containing the binaries, used by the driller node to find binaries
BINARY_DIR=None
# directory containing the pcap corpus
PCAP_DIR=None

### Driller options
# how long to drill before giving up in seconds
DRILL_TIMEOUT=None

MEM_LIMIT=None

### Fuzzer options

# how often to check for crashes in seconds
CRASH_CHECK_INTERVAL=None

# how long to fuzz before giving up in seconds
FUZZ_TIMEOUT=None

# how long before we kill a dictionary creation process
DICTIONARY_TIMEOUT=None

# how many fuzzers should be spun up when a fuzzing job is received
FUZZER_INSTANCES=None

# where the fuzzer should place it's results on the filesystem
FUZZER_WORK_DIR=None
