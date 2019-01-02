# freevulnsearch

This NMAP NSE script is part of the Free OCSAF project - https://freecybersecurity.org. In conjunction with the version scan "-sV" in NMAP, the corresponding vulnerabilities are automatically assigned using CVE (Common Vulnerabilities and Exposures) and the severity of the vulnerability is assigned using CVSS (Common Vulnerability Scoring System). For better clarity, the vulnerabilities are also assigned according to the OSSTMM Framework.

The CVEs are queried by default using the CPEs determined by NMAP via the ingenious and public API of the cve-search.org project, which is provided by circl.lu. For more information visit https://www.cve-search.org/api/ .

**Installation:**

Simply copy the NSE script freevulnsearch.nse into the corresponding script directory of the NMAP installation.
* In KALI LINUX™ for example: /usr/share/nmap/scripts/

**Usage:**

The usage is simple, just use NMAP -sV and this script.
* nmap -sV --script freevulnsearch *target*

Special thanks to the open source community for many useful ideas that accelerated the creation of this script!
Further ideas and suggestions for improvement are very welcome.

*KALI LINUX™ is a trademark of Offensive Security.*
