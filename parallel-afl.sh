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

    CHILDREN=$(pstree -p $$ | grep -o '([0-9]\+)' | grep -o '[0-9]\+' | grep -v $$)
    kill $CHILDREN 2>/dev/null

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
CREATE_DICT_PATH="$DRILLER_DIR/driller/create_dict.py"

log_info "creating dictionary of string references from the binary to improve performance"

DICTIONARY="$BINARY-driller.dict"
DICTIONARY_OPT="-x $DICTIONARY"
$CREATE_DICT_PATH $BINARY $DICTIONARY

if [[ $? == 1 ]]; then
    log_error "unable to gather string references and create dictionary, continuing anyways"
    DICTIONARY_OPT=""
fi

export AFL_PATH="$DRILLER_DIR/afl-1.83b"

MASTER_LOG="$SYNC_ID-master.log"

log_info "spinning up AFL master, logging output into $MASTER_LOG"
# spin up the master thread
$AFL_BIN -m 8G -Q $DICTIONARY_OPT -i $INPUT_DIR -o $SYNC_DIR -M "$SYNC_ID-master" -- $BINARY > $MASTER_LOG &
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

# now choose the mindless AFL slaves and the AFL slaves capable of invoking driller
AFL_SLAVES=$(($AFL_THREADS / 2))
DRILLER_SLAVES=$(($AFL_THREADS - $AFL_SLAVES))

log_info "$DRILLER_SLAVES slaves will be able to invoke driller"

for i in $(seq 1 $DRILLER_SLAVES); do
    LOG_FILE="$SYNC_ID-$i.log"
    $AFL_BIN -m 8G -Q -D "$DRILLER_PATH" $DICTIONARY_OPT -i $INPUT_DIR -o $SYNC_DIR -j $DRILLER_THREADS -S "$SYNC_ID-$i" -- $BINARY > $LOG_FILE &

    if [[ $? != 0 ]]; then
        die "unable to invoke AFL slave #$i check $LOG_FILE for likely problems"
    fi
    log_success "\t$SYNC_ID-$i, PID: $!, logfile: $LOG_FILE"
done

AFL_SLAVE_START=$(($DRILLER_SLAVES + 1))
AFL_SLAVE_END=$(($DRILLER_SLAVES + $AFL_SLAVES))
for i in $(seq $AFL_SLAVE_START $AFL_SLAVE_END); do
    LOG_FILE="$SYNC_ID-$i.log"
    $AFL_BIN -m 8G -Q $DICTIONARY_OPT -i $INPUT_DIR -o $SYNC_DIR -j $DRILLER_THREADS -S "$SYNC_ID-$i" -- $BINARY > $LOG_FILE &

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
