#!/bin/bash

set -o nounset -o pipefail -o errexit

echo "pub const $1: &[&str; 2048] = &["
sed 's/^/    "/' | sed 's/$/",/'
echo "];"
