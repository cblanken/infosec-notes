# OSINT

*Reconnaissance* is all about info gathering and can usually be done without directly interacting with the target(s) or any of their systems.

### Methodology
- [OSSTMM (Open Source Security Testing Methodology Manual) 3](https://www.isecom.org/OSSTMM.3.pdf)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [NCSC CAF (Cyber Assessment Framework)](https://www.ncsc.gov.uk/collection/caf/caf-principles-and-guidance) [Mozilla RRA (Rapid Risk Assessment)](https://infosec.mozilla.org/guidelines/risk/rapid_risk_assessment.html)

### Tools
- General Search
    - [Google](https://www.google.com)
    - [Google Dorking](https://exposingtheinvisible.org/guides/google-dorking/) / [Google Search Operators](https://ahrefs.com/blog/google-advanced-search-operators/#find-qa-threads) > [cheatsheet](google-dorking.md)
    - [Bing](https://www.bing.com)
    - [DuckDuckGo](https://www.duckduckgo.com)
    - [Internet Archive](https://archive.org/)
    - [Wikipedia](https://www.wikipedia.com)
    - [Yandex](https://yandex.com)
    - [PeopleFinder.com](https://www.PeopleFinder.com): person lookup, police records, background checks, social media etc.
    - [theHarvester](https://www.kali.org/tools/theharvester/): tool to gather OSINT on a domain
    - [DeHashed](https://dehashed.com/): paied service to search 
- IP / DNS Records / Domains / Subdomain Search
    - [assetfinder](https://github.com/tomnomnom/assetfinder): a tool to find subdomains related to a given domain
    - [AbusedIPDB](https://www.abuseipdb.com/)
    - [Expired Domains.net](https://www.expireddomains.net/): database of expired domain names and domains pending deletion
    - [Shodan](https://www.shodan.io/): open internet device search
    - [Talos Reputation Center](https://talosintelligence.com/reputation_center/lookup)
    - [crt.sh](https://crt.sh): TLS certificate database
    - [dig](https://linux.die.net/man/1/dig): CLI DNS lookup utility
    - [dnsdumpster](https://dnsdumpster.com/): dns recon & research
    - [ipify](https://www.ipify.org/): IP geolocation API
    - [ipinfo](https://ipinfo.io/)
    - [MayorSecDNSScan](https://github.com/dievus/msdnsscan): DNE enumeration tool by TheMayor
    - [nslookup](https://linux.die.net/man/1/nslookup): CLI to interactively query Internet name servers 
    - [phonebook.cz](https://phonebook.cz/): email and domain lookup based on a given domain
    - [sublist3r](https://tools.kali.org/information-gathering/sublist3r): subdomain enumuration with OSINT
    - [threatcrowd](https://threatcrowd.org/)
        - [visualping](https://visualping.io/): monitor websites for visual changes
    - [who.is](https://who.is): domain name search
        - [whois](https://linux.die.net/man/1/whois): CLI utility for `who.is`
- Email / Social Media
    - [Email Hippo](https://tools.emailhippo.com/)
    - [Have I Been Pwned](https://haveibeenpwned.com/): lookup for emails or phones in data breaches
    - [Lookup ID](https://lookup-id.com/): Facebook profile lookup
    - [Namechk](https://namechk.com/): social media username lookup
    - [Sherlock](https://github.com/sherlock-project/sherlock): tool to search usernames across social networks
    - [Twitter](https://twitter.com/)
        - [Twitter advanced search operators](https://developer.twitter.com/en/docs/twitter-api/v1/rules-and-filtering/search-operators)
        - [twint](https://github.com/twintproject/twint): a Twitter scraping and OSINT tool
    - [WeakestLink](https://github.com/shellfarmer/WeakestLink): browser extension to enumerate users from Linked company pages
    - [hunter.io](https://hunter.io/): email search
- Reverse Image Search
    - [TinEye](https://tineye.com/): reverse image search
    - [Google Search by Image](https://images.google.com/)
    - [Bing Search by Image](https://images.bing.com)
- Image Data Extraction
    - [exiftool](https://exiftool.org/): image metadata extractor 
- Maps / GPS / Location
    - [Google Maps](https://maps.google.com/)
    - [Bing Maps](https://maps.bing.com) - useful for when Google Maps censors an area
    - [Map Customizer](https://www.mapcustomizer.com/)
    - [wigle.net](https://wigle.net): catalog and map of wireless networks
- Phone / Cellphone
    - [phoneinfoga](https://github.com/sundowndev/phoneinfoga): OSINT framework for phone numbers
- Web
    - [OWASP favicon database](https://wiki.owasp.org/index.php/OWASP_favicon_database)
    - [Wappalyzer](https://www.wappalyzer.com/): website stack profiler
    - [builtwith.io](https://builtwith.com/): website stack profiler
    - [grep.app](https://grep.app/): search Github with grep, can be used to find exposed api keys, passwords etc.
- Frameworks
    - [recon-ng](https://github.com/lanmaster53/recon-ng): OSINT harvesting tool from open sources
- Knowledge Organization
    - [Maltego](https://www.maltego.com/): graphical link analysis tool for gathering and connecting information
    - [Obisdian](https://obsidian.md/): markdown editor

