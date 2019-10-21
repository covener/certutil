#!/bin/sh

BIN_DIR=`dirname ${0}`
MYJAR=$BIN_DIR/certutil.jar

if ! test -f $MYJAR; then
   $BIN_DIR/build.sh
fi

JAVA_ARGS="-DADD_CMS_SERVICE_PROVIDER_ENABLED=true"
#JAVA_ARGS=" $JAVA_ARGS -Djavax.net.debug=ALL"
java $JAVA_ARGS -jar $MYJAR "$@"
