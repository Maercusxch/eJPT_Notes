# 01_Information Gathering

We need to identify vulnerabilities and web technologies. The more you know about your target, the more successful you will be.


## Types of Information Gathering

Passive Information Gathering: Collecting information without actively engaging with the target.
Active Information Gathering: Actively engaging with the target system to collect as much information as possible (requires authorization).


## Information We Are Looking For

### Passive Information Gathering

- Identifying IP addresses & DNS information
- Identifying domain names and domain ownership information
- Identifying email addresses and social media profiles
- Identifying web technologies used on target sites
- Identifying subdomains

### Active Information Gathering
- Discovering open ports on target systems
- Learning about the internal infrastructure of a target network/organization
- Enumerating information from target systems


## Passive Information Gathering

### Website Recon & Footprinting

**What We Are Looking For:**
- IP addresses
- Hidden directories from search engines
- Names
- Email addresses
- Phone numbers
- Physical addresses
- Web technologies used

**Tools and Techniques:**
- Browser Visit the target website (e.g., hackersploit.org) and copy the IP address.
- DNS Lookup: Use host hackersploit.org to resolve the domain name to IP addresses.
- Directory and Sitemap: Check /robots.txt and /sitemap.xml for hidden directories.
- BuiltWith and Wappalyzer: Browser extensions to identify web technologies.
- Terminal: Use whatweb <domain> to analyze web technologies.
- Download Website: Use sudo apt-get install webhttrack to download the website for offline analysis.


### WHOIS Enumeration

With WHOIS Lookups you get specific informations regarding a particular Domain. WHOIS is a query and response protocol that is widely used for querying databases that store the registered users or assignees of an internet resource, such as a domain name, an IP address block or an autonomous system but is also used for a wider range of other information.

- Terminal: whois <domain> to get domain ownership and nameserver information.
- Example: whois zonetransfer.me provides nameserver information, network range (NetRange), and CIDR.


### Website Footprinting With Netcraft

- Netcraft: Shows detailed site reports including technology stack and hosting details.
- Example: Visit Netcraft and input the target domain to get a comprehensive site report.


### DNS Recon

DNSRecon is a Python script that provides the ability to perform: Check all NS Records for Zone Transfers. Enumerate General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT). Perform comman SRV Record Enumeration. Top Level Domain (TLD) Expansion.

- Terminal: dnsrecon -d <domain>
- Browser dnsdumpster.com discovers hosts related to a domain


### WAF With wafw00f

With WAFW00F, Web Application Firewall (WAF) products that protect a website can be identified and fingerprinted.

- Command to list all detectable WAFs: wafw00f -l
- Shows WAF of a specific domain: wafw00f hackersploit.org
- Browser: https://github.com/enablesecurity/wafw00f/wiki WAFW00F WIKI


### Subdomain enumeration With Sublist3r

Sublist3r is a python tool designed to enumerate subdomain of websites using OSINT(Information that is publicly available).

- Example: sublist3r -d hackersploit.org -e google,yahoo
- Browser: https://github.com/aboul3la/sublist3r Sublist3r WIKI

### Google Dorks

Google Dorks is a search technique that uses advanced operators to uncover sensitive or specific information on the Internet.

**Examples:**
- site:domain.com Limit all results to this specific domain
- site:domain.com inurl:admin searches for admin
- site:domain.com inurl:forum searches for forum
- site:*.domain.com (identifies subdomains)
- site:*.domain.com intitle:admin limits results to subdomains with Admin
- site:*.domain.com filetype:pdf(doc,docs,xlsx)
- site:domain.ch intitle:index of returns the position of the first occurrence of a value in a string
- cache:domain.com (use Wayback Machine for older versions of websites)
- site:domain.com inurl:auth_user:file.txt
- `site:domain.com inurl:passwd.txt
- Google Hacking Database https://www.exploit-db.com/google-hacking-database
### Email Harvesting With theHarvester


Is used for open source intelligence (OSINT) gathering to help determine a company's external threat landscape on the internet. The tool gathers emails, names, subdomains, IPs and URLs.

- Example: theHarvester -d <domain> -b google,linkedin


### Leaked Password Databases

- Website: Check haveibeenpwned.com for compromised accounts.


## Active Information Gathering

### DNS Zone Transfer

**DNS Records:**
- A: Resolves a hostname or domain to an IPv4 address.
- AAAA: Resolves a hostname or domain to an IPv6 address.
- NS: Reference to the domain's nameserver.
- MX: Resolves a domain to a mail server.
- CNAME: Used for domain aliases.
- TXT: Text record.
- HINFO: Host information.
- SOA: Domain authority.
- SRV: Service records.
- PTR: Resolves an IP address to a hostname.

**DNS Interrogation:**
- The process of enumerating DNS records for a specific domain to gather important information like IP addresses, subdomains, and mail server addresses.
- Command: dnsrecon -d zonetransfer.me
- DNS Zone Transfer: Copying zone files from one DNS server to another, which can be abused if misconfigured.


### Host Scanning with NMAP

NMAP is a open source tool for network exploration and security auditing.

- Interface Query: ip a s or ip a to show network interfaces and configurations.
- NMAP Ping Scan: sudo nmap -sn 172.20.10.3/28 to discover active hosts in a subnet.
- Netdiscover scan: sudo netdiscover -i eth0 -r 192.168.2.0/24


### Port Scanning with NMAP

**TCP & UDP Ports:**
- Default Scan: nmap [target IP] (SYN scan of 1000 ports, Windows systems block ICMP pings)
- Full Scan: nmap -Pn -p- [target IP] (scans all 65535 ports)
- Specific Ports: nmap -Pn -p 80,445,3389 [target IP]
- Quick Scan: nmap -Pn -F [target IP] (scans top 100 ports)

**UDP Scan:** 
- nmap -Pn -sU [target IP]


### Service and OS Detection

- Service Version Detection: nmap -Pn -sV [target IP]
- OS Detection: nmap -Pn -O [target IP]
- Default Script Scan: nmap -Pn -sC [target IP]
- Aggressive Scan: nmap -Pn -A [target IP]
- Output to File:
- Normal output: nmap -Pn -oN output.txt [target IP]
- XML output: nmap -Pn -oX output.xml [target IP]


### Adjusting Scan Speed

- Scan Speed Options: Use -T0 (paranoid) to -T5 (insane) to adjust the speed of scans.
