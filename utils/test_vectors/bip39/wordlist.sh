#!/bin/bash

set -o nounset -o pipefail -o errexit

TMP=$(mktemp -d)
trap 'rm -rf $TMP' EXIT

wget -O "$TMP/words.txt" "$1"

echo "// Copyright $(date +%Y) IOTA Stiftung"
echo "// SPDX-License-Identifier: Apache-2.0"
echo ""
echo "// $1"
echo ""
echo "pub const $2: Wordlist = Wordlist {"
echo "    separator: &\"$3\","
echo "    words: &["
sed 's/^/        "/' "$TMP/words.txt" | sed 's/$/",/'
echo "    ],"
echo "};"
