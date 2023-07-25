#!/bin/sh

set -eux

UA="$1"

if [ -z "$1" ]; then
    echo 'Missing the user agent as a first argument'
    exit 1;
fi

# Fetch digitalocean declared IPs
#curl https://digitalocean.com/geo/google.csv -s -L -# -o - | cut -d ',' -f 1 | sort | uniq > digitalocean_ips.txt

# List all routable routes for the AS 14061
#curl https://bgp.tools/table.txt -A "$UA" -s | grep -e ' 14061$' | wc -l

# Fetch all announced IPs
#curl https://bgp.tools/table.txt -A "$UA" -s | grep -e ' 14061$' | cut -d ' ' -f 1 | sort | uniq > digitalocean_announced_ips.txt

# Compare the declared IPs and announced IPs
#diff -u digitalocean_ips.txt digitalocean_announced_ips.txt > digitalocean_ips_vs_announced_ips.diff

# Generate the full IP list to check PTRs
#grep -v -F ":" digitalocean_announced_ips.txt | xargs -n1 prips > digitalocean_announced_ips_full.txt

# Some test command to get all declared reverse DNS objects at RIPE
#curl 'https://apps.db.ripe.net/db-web-ui/api/rest/fulltextsearch/select?format=json&rows=10000&q=(nserver:(digitalocean.com))%20AND%20(object-type:domain)' -H 'Accept: application/json' -A "$UA" | jq -r '.result.docs | map(.doc.strs) | .[] | map(select(.str.name=="domain")) | map(.str.value) | .[] ' > digitalocean_announced_reverse_dns.txt

# Build IPs CIDRs with found reverse DNS servers
#grep -v -F ":" digitalocean_announced_ips.txt | xargs -I {} sh -c "cidr="$(echo '{}' | cut -d '/' -f 1)"; dig +nocomments -x \$cidr | grep -v -F ';' | grep -e '.*\.in-addr\.arpa\.' | echo '{}'" > digitalocean_announced_ips_with_reverse.txt

grep -v -F ":" digitalocean_announced_ips.txt | xargs -I {} sh -c "echo '{} # $(dig +short -x {})'" > digitalocean_announced_ips_with_reverse.txt


# Fetch all reverse DNS addresses
# ns3.digitalocean.com = 198.41.222.173
cat digitalocean_announced_ips_full.txt | xargs -n 1 -P 40 dig @198.41.222.173 +short +time=5 +tries=10 -x > digitalocean_announced_ips_full_reverse.txt

# Test command
# cat digitalocean_announced_reverse_dns.txt | grep -v -F "ip6.arpa" | sed 's/.in-addr.arpa//'  | awk -F. '{print $3"." $2"."$1}' | sort | less

# A sample
#cat digitalocean_announced_ips_full.txt | xargs -n 1 -P 40 dig @198.41.222.173 +short +time=5 +tries=10 -x > digitalocean_announced_ips_full_reverse.txt

cat digitalocean_announced_ips_full.txt | xargs -P 40  -I {} sh -c 'set -eu;rev="$(dig @198.41.222.173 +short +time=5 +tries=10 -x {})";echo "{} # $rev";' > digitalocean_announced_ips_full_reverse_better.txt


grep -F -x -v -f digitalocean_announced_ips_full_reverse_better_only_ips.txt digitalocean_announced_ips_full.txt
sed -i 's/ # $//' digitalocean_announced_ips_full_reverse_better.txt
sort digitalocean_announced_ips_full_reverse_better.txt > digitalocean_announced_ips_full_reverse_better2.txt
mv digitalocean_announced_ips_full_reverse_better2.txt digitalocean_announced_ips_full_reverse_better.txt

diff -u digitalocean_announced_ips_full_reverse_better_only_ips.txt digitalocean_announced_ips_full.txt | delta
cut -d ' ' -f 1 digitalocean_announced_ips_full_reverse_better.txt > digitalocean_announced_ips_full_reverse_better_only_ips.txt

# Find all results
grep -F "stretchoid" digitalocean_announced_ips_full_reverse_better.txt | cut -d " " -f 3 | sort


# Find all ranges
grep -F "stretchoid" digitalocean_announced_ips_full_reverse_better.txt | cut -d " " -f 1 | cut -d '.' -f -3 | sort | uniq


# Make a list of search keys
grep -F "stretchoid" digitalocean_announced_ips_full_reverse_better.txt | cut -d " " -f 1 | cut -d '.' -f -3 | sort | uniq > found_ranges.txt

# Find all ranges to re-scan
cat found_ranges.txt | xargs -I {} grep -F "{}" digitalocean_announced_ips.txt | sort

# Compare with debian-scripts
grep -F "add stretchoid" stretchoid.ipset | cut -d ' ' -f 3 | cut -d '.' -f -3 | sort | uniq > found_ranges.txt
cat found_ranges.txt | xargs -I {} grep -F "{}" digitalocean_announced_ips.txt | sort > stretchoid_ranges_debian_scripts.txt


# Re scan
dig -4 +noauthority +noadditional +nostats -x 107.170.202.77 @1.0.0.1

cat stretchoid_ranges.txt | xargs -n1 prips > stretchoid_digitalocean_possible_ips.txt
# With failure handling
cat stretchoid_digitalocean_possible_ips.txt | xargs -P 50 -I {} bash -c 'set -eu;rev="$(dig @9.9.9.9 +short +time=1 +tries=1 -x {})"; if [[ "$rev" == *";;"* ]]; then sleep 1; rev="$(dig @8.8.8.8 +short +time=1 +tries=1 -x {})"; fi; echo "{} # $rev";' 1> stretchoid_revisions/v5.txt

grep -F "stretchoid" stretchoid_revisions/v5.txt | sort > stretchoid_revisions/v5.sorted.txt
mv stretchoid_revisions/v5.sorted.txt stretchoid_revisions/v5.txt

# Build the diff
diff --unified=1 stretchoid_revisions/v2.txt stretchoid_revisions/v4.txt > stretchoid_revisions/v1to2.diff

# Reverse the file
awk -F'#' '{print $2" # "$1}' OFS=, "stretchoid_revisions/v5.txt" | awk '{$1=$1;print}' | sort > stretchoid_revisions/v5-reversed.txt

# Build the count per name per ip
cat stretchoid_revisions/v*-reversed.txt | sort | uniq -c > stretchoid_revisions/count-reversed.txt
# Same but sorted not by name but by count
cat stretchoid_revisions/v*-reversed.txt | sort | uniq -c | sort > stretchoid_revisions/count-reversed.txt
