#!/bin/sh

set -eux

REV="v-$(date --iso-8601=seconds)"

cd ./digitalocean/

if [ ! -d ./binaryedge_revisions/ ]; then
    mkdir ./binaryedge_revisions
fi

if [ ! -d ./reverse_revisions/ ]; then
    mkdir ./reverse_revisions
fi

dns-ptr-resolver $PWD/binaryedge_digitalocean_possible_ips.txt 1> binaryedge_revisions/$REV.txt

grep -F "binaryedge" binaryedge_revisions/$REV.txt | sort -V > binaryedge_revisions/$REV.sorted.txt
grep -v -F "binaryedge" binaryedge_revisions/$REV.txt | sort -V > reverse_revisions/$REV.sorted.txt
mv binaryedge_revisions/$REV.sorted.txt binaryedge_revisions/$REV.txt
mv reverse_revisions/$REV.sorted.txt reverse_revisions/$REV.txt

# Reverse the file
awk -F'#' '{print $2" # "$1}' OFS=, "binaryedge_revisions/$REV.txt" | awk '{$1=$1;print}' | sort > binaryedge_revisions/$REV-reversed.txt

# Sort by name and reverse the list to build the list of all possible IPs
cat binaryedge_revisions/v*-reversed.txt | LC_ALL=C.UTF-8 sort -t "-" -n | uniq | awk -F'#' '{print "# "$1" \n "$2}' OFS='#' | awk '{$1=$1;print}' > ../binaryedge.txt

grep -F '#' ../binaryedge.txt | cut -d ' ' -f 2 | sort | cut -d. -f-1 | rev | cut -d '-' -f2- | rev | sort | uniq -c | sort > ./binaryedge-chunk-counts.txt

# Search for false positives
# cat ../binaryedge.txt | cut -d '#' -f 1 | xargs -P 50 -I {} bash -c 'set -eu;rev="$(dig @9.9.9.9 +short +time=1 +tries=1 -x {})"; if [[ "$rev" == *";;"* ]]; then sleep 1; rev="$(dig @8.8.8.8 +short +time=1 +tries=1 -x {})"; fi; echo "{} # $rev";' | grep -v -F "binaryedge.com"
