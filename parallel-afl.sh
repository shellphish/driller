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
    CUR_TIME=$(date +%s)

    RUN_UNIX=$(($CUR_TIME - $3))
    RUN_DAYS=$((RUN_UNIX / 60 / 60 / 24))
    RUN_HRS=$(((RUN_UNIX / 60 / 60) % 24))
    RUN_MINS=$(((RUN_UNIX / 60) % 60))
    RUN_SECS=$(((RUN_UNIX) % 60))

    TIME_STR=""
    if [[ $RUN_DAYS > 0 ]]; then
        TIME_STR="$RUN_DAYS "
        if [[ $RUN_DAYS > 1 ]]; then
            TIME_STR="$TIME_STR days,"
        else
            TIME_STR="$TIME_STR day,"
        fi
    fi

    if [[ $RUN_HRS > 0 ]]; then
        TIME_STR="$TIME_STR $RUN_HRS" 
        if [[ $RUN_HRS > 1 ]]; then
            TIME_STR="$TIME_STR hours,"
        else
            TIME_STR="$TIME_STR hour,"
        fi
    fi


    if [[ $RUN_MINS > 0 ]]; then
        TIME_STR="$TIME_STR $RUN_MINS" 
        if [[ $RUN_MINS > 1 ]]; then
            TIME_STR="$TIME_STR minutes,"
        else
            TIME_STR="$TIME_STR minute,"
        fi
    fi

    TIME_STR="$TIME_STR $RUN_SECS" 
    if [[ $RUN_SECS > 1 ]]; then
        TIME_STR="$TIME_STR seconds"
    else
        TIME_STR="$TIME_STR second"
    fi

    log_info real runtime: $TIME_STR

    $1/afl-1.83b/afl-whatsup $2 | tail -n 9
}

function terminate() {
    echo
    echo -e "\e[1;31m+++ Testing aborted by user +++\e[0m" 
    echo
    log_info "all fuzzers should be dead, here's afl-whatsup status to confirm"
    show_stats $1 $2 $3
    exit 1
}

if [[ $# != 6 ]]; then
    echo "usage: $0 <binary> <sync_id> <input_dir> <sync_dir> <afl-threads> <driller-threads>"
    exit 1
fi

if [[ $VIRTUAL_ENV == "" ]]; then
    die "not on a virtualenv! crashing now opposed to later!"
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

AFL_THREADS=$(($AFL_THREADS - 1))

if [[ $AFL_THREADS < 1 ]]; then
    log_error "number of afl threads specified will lead to no AFL slaves being spawned"
    echo -e "\tno drilling will ever be performed because only AFL slaves can invoke driller"
    echo -e "\tthis is probably not what you want"
else
    log_info "spinning up $AFL_THREADS AFL slaves who can each invoke $DRILLER_THREADS driller procs"
fi

for i in $(seq 1 $AFL_THREADS); do
    LOG_FILE="$SYNC_ID-$i.log"
    $AFL_BIN -m 8G -Q -D "$DRILLER_PATH" -i $INPUT_DIR -o $SYNC_DIR -j $DRILLER_THREADS -S "$SYNC_ID-$i" -- $BINARY > $LOG_FILE &

    if [[ $? != 0 ]]; then
        die "unable to invoke AFL slave #$i check $LOG_FILE for likely problems"
    fi
    log_success "\t$SYNC_ID-$i, PID: $!, logfile: $LOG_FILE"
done

START_TIME="$(date +%s)"
log_info "everything spun up at $(date -d @$START_TIME)"

trap "terminate $DRILLER_DIR $SYNC_DIR $START_TIME" SIGINT

while read line; do
    log_info "displaying summary from afl-whatsup"
    show_stats $DRILLER_DIR $SYNC_DIR $START_TIME
done
