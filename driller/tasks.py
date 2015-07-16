import redis
from celery import Celery

from .driller import Driller

app = Celery('tasks', broker='amqp://guest@localhost//', backend='redis://localhost')
redis_pool = redis.ConnectionPool(host='localhost', port=6379, db=1)

@app.task
def drill(binary, input, out_dir, fuzz_bitmap, qemu_dir):
    redis_inst = redis.Redis(connection_pool=redis_pool)

    driller = Driller(binary, input, fuzz_bitmap, qemu_dir, redis=redis_inst)
    return driller.drill()
