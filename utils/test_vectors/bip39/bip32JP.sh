#!/bin/bash

set -o nounset -o pipefail -o errexit

SCRIPT_DIR=$(readlink -f "$0" | xargs dirname)

. "$SCRIPT_DIR/../fetch.sh"

WS=$(mktemp -d)
trap 'rm -rf $WS' EXIT

# https://github.com/bip32JP/bip32JP.github.io/blob/master/test_JP_BIP39.json
fetch -s \
    "https://raw.githubusercontent.com/bip32JP/bip32JP.github.io/master/test_JP_BIP39.json" \
    "780d6a5f21827e5b455fdad35703e2c60ed9dfd47c625daaf50c01600dc4c9e2" \
    "$WS/test_JP_BIP39.json"

python <<EOF
import json
with open("$WS/test_JP_BIP39.json", "r") as f:
    tvs = json.loads(f.read())
for tv in tvs:
    print("TestVector {")
    print(f"    mnemonic: \"{bytes(tv['mnemonic'], 'utf-8').hex()}\",")
    print(f"    passphrase: \"{bytes(tv['passphrase'], 'utf-8').hex()}\",")
    print(f"    seed: \"{tv['seed']}\",")
    print("},")
EOF
