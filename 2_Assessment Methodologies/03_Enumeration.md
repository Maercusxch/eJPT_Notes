# Port Scanning and Enumeration with NMAP

### Discover, Scand and Export NMAP Scan Results (Example)

Discover available live hosts and their open ports using Nmap and identify the running services and applications.
 
- ping demo.ine.local --> bocked
- nmap demo.ine.local --> blocked
- nmap -Pn demo.ine.local --> worked
- nmap -Pn -sV -O demo.ine.local --> for ServiveVersion and OSVersion
- nmap -Pn -sV -O demo.ine.local -oX windows_server_2012 --> Creates xml file and inserts informations

### Nmap Output Formats

 - `-oN` = normal format, saves result how you see it 
 - `-oX` = xml format, offers a conversion layer and import it into metasploit framework 
 - `-oS` = Script kiddie
 - `-oG` = outputs scan results in grepable format
 - `-oA` = all 3 normal formats at once (oN, oX, oG) 
 - `-v` = Increase verbosity 
 - `--reason` = displays the reason a port is in a particular state
 - Example: `nmap -Pn -sS -F -T4 [target IP] -oN \path\filename.txt`

### Import nmap scan results in metasploit framework (xml format output):
- `service postgresql start`
- `msfconsole`
- msf6: `workspace -h`
- msf6: `workspace -a pentest_1`
- msf6: `workspace`
- msf6: `db_status`, check status, is msf connected to the postgresql database where the data is stored?
- msf6s: `dbimport nmap_xml.xml`
- msf6s: `hosts`
- msf6: `services`
- msf5: `nmap -Pn -sS -sV -O -p445 [target IP] `
- msf6s: `hosts`, metasploit framework updates file
- Grepable Format: `nmap -Pn -sS -F -T4 [target IP] -oG nmap_grep.txt`
- `cat nmap_gep.txt`, we see that its a grepable format

### Importing Nmap Scan Results into MSF

Exporting Nmap scan: `nmap -Pn -sV -O -oX nmapscan.xml demo.ine.local`
Start postgresql database service: `service postgresql start`
Start the Metasploit Framework console: `msfconsole`
Verify that the MSF database is connected: `db_status`
Import the the Nmap Scan Results: `db_import nmapscan.xml`
Check the results: `hosts` and `services`
