#!/bin/bash

SCRIPT_PATH="$(dirname $0)"
clone-cert () {
    "$SCRIPT_PATH/../clone-cert.sh" "$@"
}

rm -rf "$SCRIPT_PATH/cache"

for i in `cat $SCRIPT_PATH/cases` ; do
    clone-cert -d="$SCRIPT_PATH/cache" -r $i > /dev/null || echo $i failed
done

clone-cert -d="$SCRIPT_PATH/cache" -r \
    -c="$SCRIPT_PATH/test-ca.crt" -k="$SCRIPT_PATH/test-ca.key" \
    www.syss.de:443 > /dev/null || echo Fake CA failed

# rm -rf "$SCRIPT_PATH/cache"
