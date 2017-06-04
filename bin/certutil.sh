#!/bin/sh

BIN_DIR=`dirname ${0}`
MYJAR=$BIN_DIR/certutil.jar

if ! test -f $MYJAR; then
   $BIN_DIR/build.sh
fi

java -jar $MYJAR "$@"
