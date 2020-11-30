#!/bin/bash

set -o nounset -o pipefail -o errexit

SCRIPT_DIR=$(readlink -f "$0" | xargs dirname)

. "$SCRIPT_DIR/fetch.sh"

WS=$(mktemp -d)
trap 'rm -rf $WS' EXIT

# https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
fetch -s \
    "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip" \
    "929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8" \
    "$WS/sha.zip"

unzip -d "$WS" "$WS/sha.zip" 1>&2

if [ "$1" = "256" ]; then
    python "$SCRIPT_DIR/mangle_cavp.py" \
        "$WS/shabytetestvectors/SHA256ShortMsg.rsp" \
        "$WS/shabytetestvectors/SHA256LongMsg.rsp"
elif [ "$1" = "512" ]; then
    python "$SCRIPT_DIR/mangle_cavp.py" \
        "$WS/shabytetestvectors/SHA512ShortMsg.rsp" \
        "$WS/shabytetestvectors/SHA512LongMsg.rsp"
fi
