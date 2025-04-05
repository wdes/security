#!/bin/sh

PROJECT_ROOT="$(realpath $(dirname $0)/../)"

# Last checked: 05/04/2025
echo "Running in: $PROJECT_ROOT"

set -eu

curl -A "https://github.com/wdes/security" https://api.binaryedge.io/v1/minions | jq -r '.scanners[]' | sed '/^$/d' | sort -V > "$PROJECT_ROOT/data/scanners/binaryedge_api_ips.txt"
curl -A "https://github.com/wdes/security" https://api.binaryedge.io/v1/minions-ipv6 | jq -r '.scanners[]' | sed '/^$/d' | sort -V >> "$PROJECT_ROOT/data/scanners/binaryedge_api_ips.txt"
