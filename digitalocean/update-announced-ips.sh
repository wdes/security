#!/bin/sh

set -eu

if [ -z "${1:-}" ]; then
    echo 'Missing the user agent as a first argument'
    exit 1;
fi

UA="$1"

set -x

cd ./digitalocean/

# Fetch digitalocean declared IPs
curl https://digitalocean.com/geo/google.csv -s -L -# -o - | cut -d ',' -f 1 | sort | uniq > digitalocean_ips.txt

# List all routable routes for the AS 14061
curl https://bgp.tools/table.txt -A "$UA" -s | grep -e ' 14061$' | wc -l

# Fetch all announced IPs
curl https://bgp.tools/table.txt -A "$UA" -s | grep -e ' 14061$' | cut -d ' ' -f 1 | sort | uniq > digitalocean_announced_ips.txt

# Compare the declared IPs and announced IPs
diff -u digitalocean_ips.txt digitalocean_announced_ips.txt > digitalocean_ips_vs_announced_ips.diff

# Generate the full IP list to check PTRs
grep -v -F ":" digitalocean_announced_ips.txt | xargs -n1 prips > digitalocean_announced_ips_full.txt

# Some test command to get all declared reverse DNS objects at RIPE
#curl 'https://apps.db.ripe.net/db-web-ui/api/rest/fulltextsearch/select?format=json&rows=10000&q=(nserver:(digitalocean.com))%20AND%20(object-type:domain)' -H 'Accept: application/json' -A "$UA" | jq -r '.result.docs | map(.doc.strs) | .[] | map(select(.str.name=="domain")) | map(.str.value) | .[] ' > digitalocean_announced_reverse_dns.txt

# Build IPs CIDRs with found reverse DNS servers
grep -v -F ":" digitalocean_announced_ips.txt | xargs -I {} sh -c "cidr="$(echo '{}' | cut -d '/' -f 1)"; dig +nocomments -x \$cidr | grep -v -F ';' | grep -e '.*\.in-addr\.arpa\.' | echo '{}'" > digitalocean_announced_ips_with_reverse.txt
