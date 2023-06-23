#!/bin/sh

curl https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips | jq -r '.CLOUDFRONT_GLOBAL_IP_LIST  | join("\n")' | sort > cloudfront-ips.txt
