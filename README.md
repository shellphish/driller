### Install
    * run ./build/setup.sh to install in $PWD

This will mostly create custom QEMU versions for AFL and driller and install python packages

### Run
    ## On the driller node
        * in driller/config.py update 
            * the BROKER_URL to use the correct credential rabbitmq expects
            * the BINARY_PATH to point to a directory containing the challenge binaries
        * run `node.py` with the number of workers to create

    ## On the fuzzer node
        * in driller/config.py update
            * the BROKER_URL to point to the driller node and use the correct credentials
            * the REDIS_* settings 
        * run `run.py` with the binary, input directory, output directory and number of fuzzers

### Dependencies
    * celery
    * redis
