#!/bin/sh

set -eux

############################################################################################
#                                 Information                                              #
# The program dns-ptr-resolver can be installed from cargo: cargo install dns-ptr-resolver #
# See: https://github.com/wdes/dns-ptr-resolver                                            #
############################################################################################

REV="v-$(date --iso-8601=seconds)"

cd ./digitalocean/

if [ ! -d ./stretchoid_revisions/ ]; then
    mkdir ./stretchoid_revisions
fi

if [ ! -d ./reverse_revisions/ ]; then
    mkdir ./reverse_revisions
fi

dns-ptr-resolver $PWD/stretchoid_digitalocean_possible_ips.txt 1> stretchoid_revisions/$REV.txt

grep -F "stretchoid" stretchoid_revisions/$REV.txt | sort -V > stretchoid_revisions/$REV.sorted.txt
grep -v -F "stretchoid" stretchoid_revisions/$REV.txt | sort -V > reverse_revisions/$REV.sorted.txt
mv stretchoid_revisions/$REV.sorted.txt stretchoid_revisions/$REV.txt
mv reverse_revisions/$REV.sorted.txt reverse_revisions/$REV.txt

# Reverse the file
awk -F'#' '{print $2" # "$1}' OFS=, "stretchoid_revisions/$REV.txt" | awk '{$1=$1;print}' | sort > stretchoid_revisions/$REV-reversed.txt

# Sort by name and reverse the list to build the list of all possible IPs
cat stretchoid_revisions/v*-reversed.txt | LC_ALL=C.UTF-8 sort -t "-" -n | uniq | awk -F'#' '{print "# "$1" \n "$2}' OFS='#' | awk '{$1=$1;print}' > ../stretchoid.txt

grep -F '#' ../stretchoid.txt | cut -d- -f2 | grep -P '^[0-9]{3,}+' | sort | uniq -c | sort > ./stretchoid-chunk-counts.txt

# Search for false positives
# dns-ptr-resolver ../stretchoid.txt | grep -v -F "stretchoid.com"
