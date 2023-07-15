#! /bin/bash


DIR=/tmp/act-lurk-logs

mkdir -p $DIR
LOG=$DIR/act-$(date  +'%Y-%m-%d_%H.%M.%S').log
rm -rf $DIR/act.log
ln -sf $LOG $DIR/act.log
echo Log: $LOG
time make act 2>&1 | tee $LOG
echo Done. Log: $LOG


