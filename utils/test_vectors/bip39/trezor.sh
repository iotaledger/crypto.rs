#!/bin/bash

set -o nounset -o pipefail -o errexit

SCRIPT_DIR=$(readlink -f "$0" | xargs dirname)

. "$SCRIPT_DIR/../fetch.sh"

WS=$(mktemp -d)
trap 'rm -rf $WS' EXIT

# https://github.com/trezor/python-mnemonic/blob/master/vectors.json
fetch -s \
    "https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json" \
    "a1f7e56bc84fdec891391654ebc5e6c6cdcd70881b21a28eca4b212ad00713ad" \
    "$WS/vectors.json"

python <<EOF
import json
with open("$WS/vectors.json", "r") as f:
    tvs = json.loads(f.read())
for tv in tvs["english"]:
    print("TestVector {")
    print(f"    wordlist: wordlist::ENGLISH,")
    print(f"    entropy: \"{tv[0]}\",")
    print(f"    mnemonic: \"{bytes(tv[1], 'utf-8').hex()}\",")
    print(f"    passphrase: \"{bytes('TREZOR', 'utf-8').hex()}\",")
    print(f"    seed: \"{tv[2]}\",")
    print("},")
EOF
