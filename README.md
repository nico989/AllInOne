# AllInOne
Scripts to automate Reconnaissance step.
It performs:
- domains and subdomains enumeration.
- check for domain takeover.
- check for alive HTTP or HTTPS websites.
- take a screenshot of active websites.
- perform a fast port scan of discovered domains and subdomains.
- look for old web sites versions which might contain sensitive data or files.
- check on shodan a basic hostname query. An API KEY is needed.

# Usage
```
$ ./allInOne.sh --help
Usage: allInOne.sh [--help] [--install] --target TARGET [--key KEY]

AllInOne bash script for Reconnaissance which combines different tools to harvest information about the target.

Arguments:
  --help                   Show this help message and exit
  --install                Install and check dependencies
  --target target          Target domain
  --key KEY                Shodan API KEY
```
# Dependencies:
- whois
- assetfinder
- subfinder
- subjack
- httprobe
- whatweb
- gowitness (Google Chome headless is needed)
- nmap
- waybackurls
- shodan

# Credits
- TCM Academy: https://academy.tcm-sec.com/
