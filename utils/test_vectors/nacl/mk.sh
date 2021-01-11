#!/bin/bash

# "fun" fact:
# python's pynacl (a libsodium binding) claims to return the "Curve25519 shared secret":
# https://github.com/pyca/pynacl/blob/4a8def4fb4a246a0ac4c3adad910dec4b6497a65/src/nacl/public.py#L281
# however they return the value returned by crypto_box_beforenm:
# https://github.com/pyca/pynacl/blob/4a8def4fb4a246a0ac4c3adad910dec4b6497a65/src/nacl/public.py#L188
# which ends up in this function:
# https://github.com/jedisct1/libsodium/blob/ae4add868124a32d4e54da10f9cd99240aecc0aa/src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c#L45
# and so is the HSalsa20 of the Curve25519 shared secret (or at least something
# like that).

set -o nounset -o pipefail -o errexit

SCRIPT_DIR=$(readlink -f "$0" | xargs dirname)

. "$SCRIPT_DIR/../fetch.sh"

WS=$(mktemp -d)
trap 'rm -rf $WS' EXIT

fetch -s "http://hyperelliptic.org/nacl/nacl-20110221.tar.bz2" \
    "4f277f89735c8b0b8a6bbd043b3efb3fa1cc68a9a5da6a076507d067fc3b3bf8" \
    "$WS/nacl.tar.bz2"
mkdir "$WS/nacl"
tar -xf "$WS/nacl.tar.bz2" -C "$WS/nacl" --strip-components=1

cd "$WS/nacl"
./do

TARGET=amd64
gcc -m64 -O3 -fomit-frame-pointer -funroll-loops -o x25519 \
    -I "build/$(hostname)/include/$TARGET" \
    -L "build/$(hostname)/lib/$TARGET" \
    "$SCRIPT_DIR/x25519.c" \
    -lnacl "build/$(hostname)/lib/$TARGET/randombytes.o"

for i in $(seq 10); do
    ./x25519 | tee -a "$SCRIPT_DIR/x25519.tv"
done
