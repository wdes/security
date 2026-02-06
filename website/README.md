### Static site with responsive design
1. Adds an optional "purpose" field to API key /register POST action
2. Adds an optional "reason" field to the /report POST action
3. Allows for CIDR ranges for /report and /scan
4. Adds "scanType" field with default of "snow" to the /scan POST action, allowing for other/add'l scanners in the future 
5. Validates all IPv4 and IPv6 values to ensure they are formatted correctly and not reserved, loopback, etc (applies to /report and /scan)

_Currently untested_
