# freevulnsearch

This NMAP NSE script is part of the Free OCSAF project - https://freecybersecurity.org. In conjunction with the version scan "-sV" in NMAP, the corresponding vulnerabilities are automatically assigned using CVE (Common Vulnerabilities and Exposures) and the severity of the vulnerability is assigned using CVSS (Common Vulnerability Scoring System). For more clarity, the CVSS are still assigned to the corresponding v3.0 CVSS ratings:

* Critical (CVSS 9.0 - 10.0)
* High (CVSS 7.0 - 8.9)
* Medium (CVSS 4.0 - 6.9)
* Low (CVSS 0.1 - 3.9)
* None (CVSS 0.0)

The CVEs are queried by default using the CPEs determined by NMAP via the ingenious and public API of the cve-search.org project, which is provided by circl.lu. For more information visit https://www.cve-search.org/api/ .

**Installation:**

Simply copy the NSE script freevulnsearch.nse into the corresponding script directory of the NMAP installation.
* In KALI LINUX™ for example: /usr/share/nmap/scripts/

**Usage:**

The usage is simple, just use NMAP -sV and this script.
* nmap -sV --script freevulnsearch *target*

**CPE exception handling for format:**

If a NMAP CPE is not clear, several functions in the freevulnsearch.nse script check whether the formatting of the CPE is inaccurate. For example:

* (MySQL) 5.0.51a-3ubuntu5 -to- 5.0.51a
* (Exim smtpd) 4.90_1  -to-  4.90
* (OpenSSH) 6.6.1p1  -to-  6.6:p1
* (OpenSSH) 7.5p1  -to-  7.5:p1
* ...

Special thanks to the open source community for many useful ideas that accelerated the creation of this script!
Further ideas and suggestions for improvement are very welcome.

*KALI LINUX™ is a trademark of Offensive Security.*

*Translated with www.DeepL.com/Translator - Thanks:-)*
