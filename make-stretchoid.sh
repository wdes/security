#!/bin/sh

REV="v-$(date --iso-8601=seconds)"

cd ./digitalocean/

# With failure handling
cat stretchoid_digitalocean_possible_ips.txt | xargs -P 50 -I {} bash -c 'set -eu;rev="$(dig @9.9.9.9 +short +time=1 +tries=1 -x {})"; if [[ "$rev" == *";;"* ]]; then sleep 1; rev="$(dig @8.8.8.8 +short +time=1 +tries=1 -x {})"; fi; echo "{} # $rev";' 1> stretchoid_revisions/$REV.txt

grep -F "stretchoid" stretchoid_revisions/$REV.txt | sort -V > stretchoid_revisions/$REV.sorted.txt
mv stretchoid_revisions/$REV.sorted.txt stretchoid_revisions/$REV.txt

# Reverse the file
awk -F'#' '{print $2" # "$1}' OFS=, "stretchoid_revisions/$REV.txt" | awk '{$1=$1;print}' | sort > stretchoid_revisions/$REV-reversed.txt

# Sort by name and reverse the list to build the list of all possible IPs
cat stretchoid_revisions/v*-reversed.txt | LC_ALL=C.UTF-8 sort -t "-" -n | uniq | awk -F'#' '{print "# "$1" \n "$2}' OFS='#' | awk '{$1=$1;print}' > ../stretchoid.txt

# Search for false positives
# cat ../stretchoid.txt | cut -d '#' -f 1 | xargs -P 50 -I {} bash -c 'set -eu;rev="$(dig @9.9.9.9 +short +time=1 +tries=1 -x {})"; if [[ "$rev" == *";;"* ]]; then sleep 1; rev="$(dig @8.8.8.8 +short +time=1 +tries=1 -x {})"; fi; echo "{} # $rev";' | grep -v -F "stretchoid.com"
