### Redis Options
REDIS_HOST="localhost"
REDIS_PORT=6379
REDIS_DB=1

### Celery Options
BROKER_URL="amqp://guest@localhost//"

### Environment Options
QEMU_DIR="driller-qemu" # relative to the base directory
BINARY_DIR="/cgc/binaries/"
CRASH_CHECK_INTERVAL=60 # number of seconds to print stats and check for a crash
