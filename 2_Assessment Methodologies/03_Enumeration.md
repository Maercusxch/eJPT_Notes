# Port Scanning and Enumeration with NMAP

### Discover, Scand and Export NMAP Scan Results (Example)

 **Discover available live hosts and their open ports using Nmap and identify the running services and applications.**
 
- ping demo.ine.local --> bocked
- nmap demo.ine.local --> blocked
- nmap -Pn demo.ine.local --> worked
- nmap -Pn -sV -O demo.ine.local --> for ServiveVersion and OSVersion
- nmap -Pn -sV -O demo.ine.local -oX windows_server_2012 --> Creates xml file and inserts informations
