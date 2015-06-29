#!/bin/bash

function log_info () {
    echo -e "\e[1;94m[*]\e[0m $@" 
}

function log_success () {
    echo -e "\e[1;32m[+]\e[0m $@" 
}

function log_error() {
    echo -e "\e[1;31m[-]\e[0m $@" 
}

function die() {
    log_error $@
    exit 1
}

function show_stats() {
    $1/afl-1.83b/afl-whatsup $2 | tail -n 9
}

function terminate() {
    echo
    echo -e "\e[1;31m+++ Testing aborted by user +++\e[0m" 
    echo
    log_info "all fuzzers should be dead, here's afl-whatsup status to confirm"
    show_stats $1 $2
    exit 1
}

if [[ $# != 6 ]]; then
    echo "usage: $0 <binary> <sync_id> <input_dir> <sync_dir> <afl-threads> <driller-threads>"
    exit 1
fi

BINARY="$1"
SYNC_ID="$2"
INPUT_DIR="$3"
SYNC_DIR="$4"
AFL_THREADS="$5"
DRILLER_THREADS="$6"


pushd $(dirname $0) >/dev/null
DRILLER_DIR="$(pwd)"
popd >/dev/null

AFL_BIN="$DRILLER_DIR/driller-afl-fuzz"
DRILLER_PATH="$DRILLER_DIR/driller/drill.py"

export AFL_PATH="$DRILLER_DIR/afl-1.83b"

MASTER_LOG="$SYNC_ID-master.log"

log_info "spinning up AFL master, logging output into $MASTER_LOG"
# spin up the master thread
$AFL_BIN -m 8G -Q -i $INPUT_DIR -o $SYNC_DIR -M "$SYNC_ID-master" -- $BINARY > $MASTER_LOG &
if [[ $? != 0 ]]; then
    die "unable to invoke master AFL instance, check $MASTER_LOG for likely problems"
fi

log_success "\t$SYNC_ID-master, PID: $!, logfile: $MASTER_LOG"


log_info "spinning up $AFL_THREADS AFL slaves who can each invoke $DRILLER_THREADS driller procs"

for i in $(seq 1 $AFL_THREADS); do
    LOG_FILE="$SYNC_ID-$i.log"
    $AFL_BIN -m 8G -Q -D "$DRILLER_PATH" -i $INPUT_DIR -o $SYNC_DIR -j $DRILLER_THREADS -S "$SYNC_ID-$i" -- $BINARY > $LOG_FILE &

    if [[ $? != 0 ]]; then
        die "unable to invoke AFL slave #$i check $LOG_FILE for likely problems"
    fi
    log_success "\t$SYNC_ID-$i, PID: $!, logfile: $LOG_FILE"
done

trap "terminate $DRILLER_DIR $SYNC_DIR" SIGINT

while read line; do
    log_info "displaying summary from afl-whatsup"
    show_stats $DRILLER_DIR $SYNC_DIR
done
