#!/bin/sh

set -eu

# See: https://stackoverflow.com/a/69768584/5155484
curl -f -s -# https://ip-ranges.amazonaws.com/ip-ranges.json | jq -r '.prefixes[] | select(.service == "CLOUDFRONT") | .ip_prefix' | sort -V > cloudfront-ips.txt
curl -f -s -# https://ip-ranges.amazonaws.com/ip-ranges.json | jq -r '.ipv6_prefixes[] | select(.service == "CLOUDFRONT") | .ipv6_prefix' | sort -V >> cloudfront-ips.txt

# Does not seem up to date: 06-2023
#curl https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips | jq -r '.CLOUDFRONT_GLOBAL_IP_LIST  | join("\n")' | sort > cloudfront-ips.txt
