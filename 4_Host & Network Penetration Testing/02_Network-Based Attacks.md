# Network Based Attacks

## Networking

### Firewall Detection and IDS Evasion

**NMAP Scans**

- `nmap -sA -p 445,3389 <IP-Address>` To check if this ports are filtered by sending ACK packets
- `nmap -f -p 445,3389 <IP-Address>` Sends fragmented Packages. Without fragmentation, large packets might be rejected by some network paths, leading to communication failures.
- `nmap -p 445,3389 -D <Decoy-IP> <Your IP>` This is a decoy option. We make the scan look like it comes from the gateway IP. You need to be connected to the Network for this scan.
- `nmap -p 445,3389 -g 53 -D <Decoy-IP> <Your IP>` Sets the source-port to 53, so it looks like it is a DNS request/message.
- `nmap -p 445,3389 --ttl <value> <IP-Address>` Set the IP time to live field
- `nmap --data-lenght <value> -p 445,3389 <IP-Address>` This option tells Nmap to append the given number of random bytes to most of the packets it sends, and not to use any protocol-specific payloads.
- `nmap -n -p 445,3389 <IP-Address>` disables DNS resolution in Nmap.


## Network Attacks

