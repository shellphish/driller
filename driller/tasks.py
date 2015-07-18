import redis
from celery import Celery

from .driller import Driller
import config

backend_url = "redis://%s:%d" % (config.REDIS_HOST, config.REDIS_PORT)
app = Celery('tasks', broker=config.BROKER_URL, backend=backend_url)
redis_pool = redis.ConnectionPool(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)

@app.task
def drill(binary, input, fuzz_bitmap, qemu_dir):
    redis_inst = redis.Redis(connection_pool=redis_pool)

    driller = Driller(binary, input, fuzz_bitmap, qemu_dir, redis=redis_inst)
    return driller.drill()
