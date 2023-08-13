#!/bin/sh

set -eux

############################################################################################
#                                 Information                                              #
# The program dns-ptr-resolver can be installed from cargo: cargo install dns-ptr-resolver #
# See: https://github.com/wdes/dns-ptr-resolver                                            #
############################################################################################

REV="v-$(date --iso-8601=seconds)"

cd ./digitalocean/

if [ ! -d ./binaryedge_revisions/ ]; then
    mkdir ./binaryedge_revisions
fi

if [ ! -d ./reverse_revisions/ ]; then
    mkdir ./reverse_revisions
fi

curl -A "https://github.com/datacenters-network/security" https://api.binaryedge.io/v1/minions | jq -r '.scanners[]' | sed '/^$/d' | sort -V > ./binaryedge_api_ips.txt
curl -A "https://github.com/datacenters-network/security" https://api.binaryedge.io/v1/minions-ipv6 | jq -r '.scanners[]' | sed '/^$/d' | sort -V >> ./binaryedge_api_ips.txt

doRev () {
    dns-ptr-resolver $PWD/$1 1> binaryedge_revisions/$REV.txt

    grep -F "binaryedge" binaryedge_revisions/$REV.txt | sort -V > binaryedge_revisions/$REV.sorted.txt
    grep -v -F "binaryedge" binaryedge_revisions/$REV.txt | sort -V > reverse_revisions/$REV.sorted.txt
    mv binaryedge_revisions/$REV.sorted.txt binaryedge_revisions/$REV.txt
    mv reverse_revisions/$REV.sorted.txt reverse_revisions/$REV.txt

    # Reverse the file
    awk -F'#' '{print $2" # "$1}' OFS=, "binaryedge_revisions/$REV.txt" | awk '{$1=$1;print}' | sort > binaryedge_revisions/$REV-reversed.txt

    # Sort by name and reverse the list to build the list of all possible IPs
    cat binaryedge_revisions/v*-reversed.txt | LC_ALL=C.UTF-8 sort -t "-" -n | uniq | awk -F'#' '{print "# "$1" \n "$2}' OFS='#' | awk '{$1=$1;print}' > ../binaryedge.txt

    grep -F '#' ../binaryedge.txt | cut -d ' ' -f 2 | sort | cut -d. -f-1 | rev | cut -d '-' -f2- | rev | sort | uniq -c | sort > ./binaryedge-chunk-counts.txt
}

doRev "binaryedge_api_ips.txt"
doRev "binaryedge_digitalocean_possible_ips.txt"

# Search for false positives
# dns-ptr-resolver ../binaryedge.txt | grep -v -F "binaryedge.com"
