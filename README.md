# Wdes SAS security toolkit

## Security lists

### Scanners

- `https://security.wdes.eu/scanners/stretchoid.txt` (List of all known stretchoid IPs)
- `https://security.wdes.eu/scanners/binaryedge.txt` (List of all known binaryedge IPs)
- `https://security.wdes.eu/scanners/shadowserver.txt` (List of all known shadowserver (shadowserver.org) IPs)
- `https://security.wdes.eu/scanners/censys.txt` (List of all IPs declared by censys scanner (censys.io) on their [FAQ](https://docs.censys.com/docs/opt-out-of-data-collection)
- `https://security.wdes.eu/scanners/internet-measurement.com.txt` (List of all IPs declared by internet-measurement.com on [their website](https://internet-measurement.com/#ips))
- `https://security.wdes.eu/scanners/anssi.txt` (List of all IPs declared by CERT-FR/ANSSI on [their website](https://www.cert.ssi.gouv.fr/scans/))

### Collections (by vendor)

- `https://security.wdes.eu/collections/wdes/bad-networks.txt` (List of some hand picked bad networks)
- `https://security.wdes.eu/collections/wdes/bad-ips.txt` (List of some hand picked bad IPs that caused harm/attacks/scans to mail servers)

- `https://security.wdes.eu/collections/microsoft/email-servers.txt` (List of the [Microsoft IPs for it's mail servers](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide#exchange-online))
- `https://security.wdes.eu/collections/amazon/cloudfront-ips.txt` (List of AWS CloudFront IPs)

## Other similar projects

- https://github.com/szepeviktor/debian-server-tools/tree/master/security/myattackers-ipsets/ipset
- https://github.com/wravoc/authlog-threats/blob/main/scanners (not updated in 2025 since two years)
- https://github.com/stamparm/maltrail/blob/master/trails/static/mass_scanner.txt

## TODO list

### Features

- https://security.wdes.eu/scanners/<scanner>.txt#commented -> Output with the name

### Scanners

  - *.scan.bufferover.run example: bogota.scan.bufferover.run
  - optout.scanopticon.com
  - pinger*.netsec.colostate.edu
  - pinger-*.ant.isi.edu
  - researchscanner*.eecs.berkeley.edu
  - researchscan*.eecs.umich.edu
  - researchscan*.comsys.rwth-aachen.de
  - scanners.labs.rapid7.com, scanner*.labs.rapid7.com
  - openresolverproject.org, opensnmpproject.org, openntpproject.org, openssdpproject.org, openresolverproject.org
  - probe*.projectblindferret.com
  - shodan.io, *.census.shodan.io, census*.shodan.io
  - kudelskisecurity.com
  - riskiq.com
  - scan.sba-research.org, scanning.sba-research.org
  - 5thcolumn.net
  - internet-census.org, ca-san-*-*-*.internet-census.org, Example: zl-ams-nl-gr1-wk102b.internet-census.org
  - internettl.org
  - netsystemsresearch.com
  - tequilaboomboom.club
  - scanner.openportstats.com
  - outspoken.ca
  - phenome.ca
  - ltx71
  - Greenbone
  - leakix.net
  - [45.83.64.0/22 is ALPHASTRIKE-RESEARCH](https://www.alphastrike.io/en/log4j/)
  - security.criminalip.com
