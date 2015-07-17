### Install
    * run ./build/setup.sh to install in $PWD

This will mostly create custom QEMU versions for AFL and driller and install python packages

### Run
    * cd <challenge-binary>
    # driller must be on the PYTHONPATH and N is the number of workers
    * celery -A driller.tasks worker -c N --loglevel=info 
    * python ../listen.py -o <sync_dir>/driller <challenge-binary>

    this will all be replaced with a nice script soon 

### Dependencies
    * celery
    * redis
