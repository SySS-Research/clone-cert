#!/bin/bash

SCRIPT_PATH="$(dirname $0)"
clone-cert () {
    "$SCRIPT_PATH/../clone-cert.sh" "$@"
}

rm -rf "$SCRIPT_PATH/cache"

for i in `cat $SCRIPT_PATH/cases` ; do
    clone-cert -d="$SCRIPT_PATH/cache" -r $i > /dev/null || echo $i failed
done

# rm -rf "$SCRIPT_PATH/cache"
