#!/bin/sh

BIN_DIR=`dirname ${0}`
TARGET_DIR=$BIN_DIR/../target/

if ! ls -1 $TARGET_DIR/certutil-*.jar 2>/dev/null >/dev/null; then
  mvn compile assembly:single
fi

java -jar $BIN_DIR/../target/certutil*.jar "$@"
