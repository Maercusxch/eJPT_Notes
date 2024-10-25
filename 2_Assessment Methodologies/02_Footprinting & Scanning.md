# Networking Primer


It involves scanning open ports, mapping network topologies, and collecting information about hosts, their operating systems, IP addresses, and user accounts. This gathered data helps to generate a comprehensive technical blueprint of the target organization.

## Networking Fundamentals

### Packets

The primary goal of networking is the exchange of information between networking computers; this information is transferred by packets. Packets are more nothing but streams of bits running as electric signals on physical media used for data transmission(Ethernet, Wi-Fi etc). These electrical signals are then interpreted as bits (zeros and ones) that make up the information.
![Packets](https://github.com/user-attachments/assets/c6040f83-2172-434a-ac42-d3d1515fb712)

- **Header:** The header contains information about the packet, such as its origin and destination IP addresses
The header has a protocol-specific structure: this ensures that the receiving host can correctly interpret the payload and handle the overall communication.
- **Payload:** The Payload is the actual Data.


### ISO OSI Modell

![ISO OSI Modell](https://github.com/user-attachments/assets/682c0e1d-835c-4713-acb2-d79aaa6bdef5)



## Network Layer


The Network Layer is responsible for logical addressing, routing, and forwarding data packets between devices across diffrent networks. The networklayer abstracts the underlying physical network, allowing for the creation of a cohesive internetwork.


### Network Layer Protocols 

- IPv4(Internet Protocol version 4)
- IPv6(Internet Protocol version 6)
- ICMP(Internet Control Message Protocol) Used for error reporting and diagnostics. ICMP messages include ping (echo request and echo reply), traceroute, and various error messages.


### IPv4 Addresses

- IPv4 address consists of four bytes, or octets; a byte consists of 8 bits.
- A dot delimits every octet in the address.


### Reserved IPv4 Addresses

0.0.0.0 - 0.255.255.255 representing "this" network.
127.0.0.0 - 127.255.255.255 representing the local host
192.168.0.0 - 192.168.255.255 reserved for private networks.


### IP Functionality

**Logial Addressing**
- IP addresses serve as logical addresses assigned to network interfaces. These addresses uniquely identify each device on a network.
- IP adresses are hierarchical and structured based on network classes, subnets, and CIDR(Classless Inter- Domain Routing) notation.

**Packet Structure**
- IP organzies data into packets for transmission across networks. Each packet consists of a header and payload.
- Header contains essential information, including the source and destination IP addresses, version number, time to live (TTL), and protocol type

**Fragmentation and Reassembly**
- IP allows for the fragmentation of large packets into smaller fragments when traversing networks with varying Maxium Transmisson Unit (MTU) sizes.
- The recieving host reassembles these fragments to reconstruct the original packet.

**IP Addressing Types**
- There are three types: unicast (one-to-one communication). broadcast (one-to-all communication within a subnet). and multicast (one-to-many communication to a selected group of devices).

**Subnetting**
- technique to divide a large IP network into smaller, more manageable sub-networks. It enhances network efficiency and security.

**Internet Control Message Protocol (ICMP)**
- ICMP is closely associated with IP and is used for error reporting and diagnostics. Common ICMP messages include echo request and echo reply, which are used in the ping utility

**Dynamic Host Configuration Protocol(DHCP)**
- DHCP is oftem used in conjunction with IP to dynamically assign IP addresses to devices on a network, simplifying the process of network configuration


### IP Header Format

 The IP protocol defines many different fields in the packet header. These fields contain binary values that the IPv4 services reference as they forward packets across the network.

**Most Important ones to know:**
- IP source address - Packet Source
- IP Destination Address - Packet Destination
- Time-to-Live (TTL) - An 8-bit value that indicates the remaining lifespan of the packet.
- Type-of-Service (ToS) - The Type-of-Service field contains an 8-bit binary value that is used to determine the priority of each packet.
- Protocol - This 8-bit value indicates the data payload type that the packet is carrying.


### IPv4 Header Fields


| Field         | Purpose       |
| ------------- | ------------- |
| Version (4 bits)|Indicates the version of the IP protocol being used. For IPv4, the value is 4.|
| Header Length (4 bits) | Specifies the lenght of the IPv4 in 32-bit words. The minimum value is 5, indicating a 60-byte header.  |
| Type of Service (8 bits) | Originally designed for specifying the quality of service, it includes fields such as Differentiated Services Code Point (DSCP) and Explicit Congestion Notification (ECN) to manage packet priority and congestion control.|
| Total Lenght (16 bits) | Represents the total size of the IP packet, including both the header and the payload. The maximum size is 65.535 bytes |
|Identification (16 bits) | Is used for reassembling fragmented packets. Each Fragment of a packet is assigned the same identification value. |
| Flags (3 bits) | Includes three flags related to packet fragmentation, when beeing performed: 1): Reserved (bit 0): Always set to 0.  2): Don't Fragment (DF, bit 1): if set to 1, indicates that the packet should not be fragmented.  3): More Fragments (MF, bit 2): If set to 1, indicates that more fragments follow in a fragmented packet.|
| Time to Live (TTL,8 bits) |  Represents the maximum number of hops a packet can traverse befor being discarded. It is decremented by one at each hop. |
| Protocol (8 bits) | Identifies the higher-layer protocol that will receive the packet after IP processing. Common values include 6 for TCP, 17 for UDP and 1 for ICMP. |
|Source IP Address (32 bits) |Specifies the IPv4 address of the sender (source) of the packet.|
|Destination IP Address (32 bits) |Specifies the IPv4 address of the intended recipient (destination) of the packet.|


### IP Header Format

![image](https://github.com/user-attachments/assets/69484e38-3ce7-4df4-aa62-68a113abae50)



## Transport Layer

The Transport layer fourth layer of the OSI model, plays a crucial role in faciliating communication between two devices across a network. This layer enrsures end-to-end communication, handling tasks such as error detection, flow control, segmentation of data into smaller units. Is responsible for providing end-to-end communication and ensuring the reliable and ordered delivery of data between two devices on a network.


### Transpost Layer Protocols

- **TCP** (Transmission Control Protocol): Connection-oriented protocol providing reliable and ordered delivery of data.
- **UDP** (User Datagram Protocol): Connectionless protocol that is faster but provides no guarantees regarding the order or reliability of data delivery.

### TCP vs UDP 

![image](https://github.com/user-attachments/assets/6f788dcf-2a97-4927-a18f-039d778b764b)
`netstat -antp` to see TCP connections Windows: `netstat -ano` to see TCP connections



## TCP(Transmission Control Protocol)

TCP is one of the main protocols operating at the Transport Layer (Layer 4) of the OSI model. TCP is a connection oriented, reliable protocol that provides a dependable and ordered delivery of data between two devices over a network. It ensures, that data sent from one application on a device is recieved accurately and in the correct order by another application on a different device.

### TCP characteristics

- **Connection-Oriented:** TCP establishes a connection between the sender and receiver before any data is exchanged. This connection is a virtual circuit that ensures reliable and ordered data transfer.
- **Reliability:** TCP guarantees reliable delivery of data. It achieves this through mechanisms such as acknowledgements (ACK) and retransmissions of lost or corrupted packets. If a segment of data is not acknowledged. TCP automatically resends the segment.
- **Ordered Data Transfer:** TCP ensures that data is delivered in the correct order. If segments of data arrive out of order, TCP reorders them before passing them to the higher-layer application.


### TCP 3-Way Handshake 

The TCP three-way handshake is a process used to establish a reliable connection between two devices before they begin data transmission. It involves a series of three messages exchanged between the sender (client) and the reciever (server). Before a HTTP request can happen, a TCP 3-Way Handshake must happen.

![image](https://github.com/user-attachments/assets/1f40e1f2-bb42-40f2-ba96-ffd4d1226923)

- **Syn** (Synchronize): process begins with the client sending a TCP segment with the SYN flag set. This initial message indicates the client's intention to establish a connection and includes an initial sequence number (ISN), which is a randomly chosen value.
- **SYN-ACK** (Synchronize-Acknowledge): Upon recieving the SYN segment, the server responds with a TCP segment that has both the SYN and ACK (Acknowledge) flags set. The acknowledgment (ACK) number is set to one more than the initial sequence number recieved in the client's SYN segment. The server also generates its own initial sequence number.
- **ACK** (Acknowledge): Finally, the client acknowledges the server's response by sending a TCP segment with the ACK flag set. The acknowledgment number is set to one more than the server's initial sequence number. 
After the three-way handshake is complete, the devices can exchange data in both directions. The achnowledgment numbers in subsequent segments are used to confirm the receipt of data and to manage the flow of information.


### TCP Header Fields

![image](https://github.com/user-attachments/assets/35ea7795-d651-4b92-bef7-521345ad3d63)


### TCP Control Flags

TCP uses a set of control flags to manage various aspects of the communication process. These flags are included in the TCP header and control diffrent features during the establishment, maintenance, and termination of a TCP connection.

**Establishing a Connection (from client):**
- SYN(Set): Initiates a connection request.
- ACK(Clear): No acknowledgment yet.
- FIN(Clear): No termination request.

**Establishing a Connection (Response)(from server or system):**
- SYN(Set): Acknowledges the connection request.
- ACK(Set): Acknowledges the received data.
- FIN(Clear): No termination request.

**Terminating a Connection (from client):**
- SYN(Clear): No connection request.
- ACK(Set): Acknowledges the received data.
- FIN(Set): Initiates connection termination.


### TCP Port Range

TCP uses port numbers to distinguish between diffrent services or applications on a device. Port numbers are 16-bit unsigned integers, and they are divided into three ranges. The maximum port number in the TCP/IP protocol suite is 65,535.

**Well-Known Ports (0-1023):** Port numbers from 1023 are reserved for well-known services and protocols. These are standarized by the Internet Assigned Numbers Authority (IANA). Examples include:
- 80: HTTP (Hypertext Transfer Protocol)
- 443: HTTPS (HTTP Secure)
- 21: FTP (File Transfer Protocol)
- 22 SSH (Secure Shell)
- 25: SMTP (Simple Mail Transfer Protocol)
- 110: POP3 (Post Office Protocol version 3)

**Registered Ports (1024-49151):** Port numbers from 1024 to 49151 are registered for specific services or applications. These are typically assigned by the IANA to software vendors or developers for their applications. While they are not standarized, they are often used for well-known services. Example include:
- 3389: RDP
- 3306: MySQL Database
- 8080 HTTP alternate port
- 27017: MongoDB Database
- example: if 3389 Port is open on a windows machine, most likely that system is running rdp (or allows connection)


## UDP(User Datagram Protocol)

UDP is a connectionless and lightweight transport layer protocol that provides a simple and minimalistic way to transmit data between devices on a network. UPD does not establish a connection before sending data and does not provide the same level of reliability and ordering guarantees as TCP. Instead, it focuses on simplicity and efficiency, making it suitable for certain types of applications.


### UDP characteristics

- **Connectionless:** UDP is a connectionless protocol, it doesnt establish a connection before sending data. Each UDP packet (datagram) is treated independently, and there is no persistent state maintained between sender and reciever.
- **Unreliable:** UDP does not provide reliable delivery of data. It does not guarantee that packets will be delivered, and there is no mechanism for retransmission of lost packets. This lack of reliability makes UDP faster but less suitable for applications that require guaranteed delivery.
- **Used for Real-Time Applications:** UDP is commonly used in real-time applications where low latency is crucial, such as audio and video streaming, online gaming, and voice-over-IP (VoIP) communication.
- **Simple and Stateless:** UDP is a stateless protocol meaining that it does not maintain any state informaion about the communication.
- **Independence:** Each UDP packet is independent of previous or future packets.


 
# Host Discovery

## Network Mapping

After collecting information about a target organization during the passive information gathering sage, a penetration tester typically moves n to active information gathering phase which involves discovering hosts on a network, perfoming port scanning and enumeration. Every host connected to the Internet or a private network must have a unique IP address that uniquely identifies it on a said network. How can a pentester determine what hosts, within an in-scope network are online? what ports are oopen on the active hosts? and what operating sytems are running on the active hosts? Answer - Network Mapping. Network mapping in the context of pentesting refers to the process of discovering and identifying devices, hosts, and network infrastructure elements within a target network. Pentesters use network mapping as a crucial initial step to gather information about the network's layout, understand its architecture, and identify potential entry points for further exploitation.

**Example:**
A company asks for you/your company to perform a pentest, and the following address block is considered in scope: 200.200.0.0/16. A sixteen-bit long netmask means the could contain up to 216 (65536) hosts with IP addresses in the 200.200.0.0 - 200.200.255.255 range. The first job for the pentester will involve determining which of the 65536 IP addresses are assigned to a host, and which of those hosts are online/active. 

![image](https://github.com/user-attachments/assets/9529cf96-18c9-4e55-8a7e-19318308b6d2)
![image](https://github.com/user-attachments/assets/dbd1a4cd-3504-4223-8cb8-b0483d931307)


### Network Mapping Objective

- **Discovery of Live Hosts:** Identifying active devices and hosts on the network. This involves determining which IP addresses are currently in use.
- **Identification of Open Ports and Services:** Determining which ports are open on the discovered hosts and identifying the services running on those ports. This information helps pentesters understand the attack surface and potential vulnerabilities.
- **Network Topology Mapping:** Creating a map or diagram of the network topology including routers, switches, firewalls, and ohter network infrastructure elements. Understanding the layout of the network assists in planning further pentesting activites.
- **Operating System Fingerprining:** Determining the operating systems running on discovered hosts. Knowing the operating system helps pentesters tailor their attack strategies to target vulnerabilities specific to that OS. example: If you perform a blackbox pentest and you discover that the target network is a windows environment or AD domain, you can focus your attention on Windows/AD specific attacks.
- **Serice Version Detection:** Identifying specific versions of services running on open ports. This informtion is crucial for pinpointing vulnerabilities associated with particular service versions.
- **Identifying Filtering and Security Measures:** Discovering firewalls, intrusion prevention systems, and other security measures in place. This helps pentesters understand the network's defenses and plan their approach accordingly.


### Nmap (Network Mapper) & Nmap Functionality

- **Usage:** Used for discovering hosts and services on a computer network, finding open ports, and identifying potential vulnerabilites.
- **Host Discovery:** Nmap can identify live hosts on a network using techniques such as ICMP echo requests, ARP requests, or TCP/UDP probes.
- **Port Scanning:** It can perform various types of port scans to discover open ports on target hosts.
- **Service Version Detection:** Nmap can determine the versions of services running on open ports. This info helps in understanding the software stack and potential vulnerabilites associated with specific versions.
- **Operating System Fingerprinting:** Nmap can attempt to identify the operating system od target hosts based on characteristics observed during the scanning process.


### Host Discovery Techniques

In pentesting, host discovery is a crucial phase to identify live hosts on a network before further exploration and vulnerability assessment. Various techniques can be employed for host discovery, and the choice of technique depends on factors such as network characteristics, stealth requirements, and the goals of the penetration test.

**Important**: A TCP Reset (RST) packet is used by a TCP sender to indicate that it will neither accept nor receive more data. 

- **Ping Sweeps (ICMP Echo Requests):** Sending ICMP Echo Requests (ping) to a range of IP addresses to identify live hosts.
- **ARP Scanning:** Using Address Resolution Protocol (ARP) requests to identify hosts within the same broadcast domain.
- **TCP Syn Ping (Half-Open Scan):** Sending TCP SYN packets to a specific port (often port 80) to a check if a host is alive. If the host is alive, it respends with a TCP SYN-ACK. This technique is stealthier than ICMP ping.
- **UDP Ping:** Sending UDP packets to a specific port to check if a host is alive. This can be effective for hosts that do not respond to ICMP or TCP probes.
- **TCP Ack Ping:** Sending TCP Ack packets to a specific port to check if a host is alive. This technique expects no response, but if a TCP RST (reset) is recieved, it indicates that the host is alive.
- **SYN-ACK Ping (Sends SYN-ACK packets):** Sending TCP SYN-ACK packets to a specific port to check if a host is alive. If a TCP RST is recieved, it indicates that the host is alive

To enumerate the best host discovery technique for your needs, there are some considerations you need to keep in mind:

**ICMP Ping:**
- Pros: ICMP ping is a widely supported and quick method for identifying live hosts.
- Cons: Some hosts or firewally may be configured to block ICMP traffic, limiting its effectiveness. ICMP ping can also be easily detected.

**TCP SYN Ping:**
- Pros: TCP SYN ping is stealthier than ICMP and may bypass firewalls that allow outbond connections.
- Cons: Some hosts may not respond to TCP SYN requests, and the results can be affected by firewalls and security devices.


## Ping Sweeps

A ping sweep is a network scanning technique used to discover live hosts within a specific IP address range on a network. The basic idea is to send a series of ICMP Echo Request (ping) messages to a range of IP addresses and observe the responses to determine which addresses are active or reachable.
**Important:** Windows will block ICMP requests by default.
Ping sweeps work by sending one or more specially crafted ICMP packets (Type 8 - echo request) to a host.
If the host ist alive, the host replies with ICMP echo reply (Type 0) packet.
**ICMP Echo Request:**
- Type: 8
- Code: 0 
**ICMP Echo Reply:**
- Type: 0
- Code: 0

The "Type" field in the ICMP header indicates the purpose/function of the ICMP message, and the "Code" field provides additional information or context related to the message type.
The Type value 8 represents Echo Request and the Type value 0 represents Echo Reply.*
When Host is offline, the host will not recieve a IMCP Echo Reply.
No response doesn't mean that the host is permanently offline; it also could be network congestion, temporary unavailability, or firewall setting that block ICMP traffic.


### Practical Ping Sweeps Commands 

Example IP: [target IP]
- **Terminal & CMD**: `ping [target IP]` normal Ping request
- **Terminal**: `ping -c 5[target IP] ` specify amount of packets you send
- **CMD**: `ping -n 5 [target IP] ` specify amount of packets you send
- **Terminal**: `ping 192.168.1.0` Pings every IP in subnet
- **Terminal**: `man fping` description fping
- **Terminal**: `fping -h` fping help menue
- **Terminal**: `fping -a [target IP]` normal fping request
- **Terminal**: `fping -a -g 192.168.1.0/24` Pings every IP in subnet and gives feedback to it 
- **Terminal**: `fping -a -g 192.168.1.0/24 2>/dev/null` shows only online IP's in that subnet



## Host discovery with NMAP

Wireshark Scan for a specific network connection: `sudo wireshark -i eth1`

- `ifconfig` displays only the enabled network interfaces that are connected to the system.

NMAP Format: `nmap scanoptions target`
- `nmap -help` `man nmap` Help and description NMAP   /-sn to search in man nmap
- `nmap -sn 192.168.1.0/24` Scans the whole domain
- `nmap -sn 192.168.1.0 - 100 Scans this specific Ip range.

when you are connected to a physical connected network, sn / ping scan will utilize ARP protocol to perform Host discovery.
The -sn command in Nmap only performs a host discovery scan without scanning ports.

- `nmap -sn 192.168.1.0/24 --send-ip` Now ICMP echo requests should also been sent
- `nmap -sn [target IP] 192.168.1.105` Scans more than one IP
- `vim targets.txt` here you can insert IP's without typing manually
- `nmap -sn -iL targets.txt` scans the IPs in the text file


### TCP SIN PING:

- By default, it will send a tcp syn packet to port 80 on the target system. If port closed, host responses with RSD packet. if port is open, host response with TCP syn-ack packet = connection established. after that, an RSD packet is sent to reset that connection.
In some cases, firewalls are configured to drop RSD packets, custom ports need to be specified. this is a way to perform port scanning with multiple IP
- `nmap -sn -PS`: `-sn` = no port scan, `-PS` = override packets that the ping sends, specify TCP SYN ping. This command will send a SYN packet to the target on port 80. If host is online and port 80 is open, it will respond with a SYN-ACK. if closed, port will response with a RSD packet. If no response, its offline.
- Using `nmap -sn -PS [target IP]` is more effective in environments where ICMP traffic is restricted but TCP traffic is allowed. It provides a way to discover hosts that may not respond to standard ICMP echo requests.
- `nmap -sn -PS22 [target IP]` scans the port 22 instead of the port 80
- `nmap -sn -PS22-1000 [target IP]` scans all ports between 1 and 1000


### TCP ACK PING

NMAP will send a TCP Packet with ACK flagset to Port 80 of the target system. If it is acitve, it will return a RST packet.

- `nmap -sn -PA [target IP]`

ACK Ping gets blocked by systems. not reliable. ACK Scan is good for utilize if theres a firewall


### ICMP SPECIFIC PING SCAN

Only ICMP eco requests are sent and not combined with any of the other packets we were using with the ping scan options.

- `nmap -sn -PE [target IP]`
- `nmap -sn -PE [target IP] --send-ip` 



## Port Scanning, Service Version & OS Detection

### Port Scanning with NMAP

NMAP will send a SYN packet to the target port, if the target port is open, it will response with a SYN-ACK packet. If it is closed it will respond with a RST packet. If nmap doesnt recieve a SYN-ACK or RST, there is a firewall or the filter. The port still can be open.

- `nmap [target IP]` SYN port scan to 1000 most common ports 
- `nmap -Pn [target IP]` same command but without ping
- `nmap -F [target IP]` F stands for Fast and scans only 100 of the most common ports
- `nmap -Pn -p 80 [target IP]` Specify specific port scan(80)
- `nmap -Pn -p80,445,3389,8080 [target IP]` Specify multiple port scan (80,445,3389,8080)(If result =filtered: Windows firewall. When closed: No firewall)
- `nmap -Pn -p1-100 [target IP]` Specify specific port range (1-100)
- `nmap -Pn -p- [target IP]` Scans entire TCP Port range
- `nmap -Pn -sU -p [target IP]` Scan for udp ports

If non privileged user:
- `nmap -Pn -sS [target IP]`
- `nmap -Pn -sT [target IP]` TCP connect scan, default port scanning if no root or sudo. Loud on a network, gets detected easily. Completes the 3-way-handshake.


### Service Version & OS Detection with NMAP

- Service Version: `-sV` Example: `nmap -T4 -sS -sV -p- [target IP]`
- Operating System(OS) Version: `-O` Example: `nmap -T4 -sS -sV -O -p- [target IP]`
- Aggressive OS Version: `--osscan-guess` Example: `nmap -T4 -sS -sV -O --osscan-guess -p- [target IP]`
- Aggressive Service Version: `--version-intensity 1-9` Example: `nmap -T4 -sS -sV --version-intensity 8 -O --osscan-guess -p- [target IP]`


### Nmap Scripting Engine (NSE)

NSE allows users to write and share scripts to automate a wide range of tasks. It is essentially designed to facilitate the automation of various tasks. It was created to automate and facilitate port scanning, service version detection, vulnerability scanning, exploitation, brute forcing, etc. Nmap scripts have the extension `.nse` and are programmed in the lua programming language.

- `ls -al /usr/share/nmap/scripts/` Directory for already created and verified scripts
- `ls -al /usr/share/nmap/scripts/ | grep -e "http"` limits the results to only http scripts
- Example: `http-enum.nse` performs basic http enumeration
- 
`nmap -sS -sV -sC -p- -T4 [target IP]` :Default nmap script scan. Provides us OS, kernel etc.
Now, i could look for vulnerabilites that affect the version of mongoDB or ubuntu (target OS) check, which other mongoDB scripts are available. `nmap --help-help=mongodb-databases`
`nmap -sS -sV --script=mongodb-info -p- -T4 [target IP]` run sycript
Another service that is running is memcached, so we check for memcached scripts: `ls -al /usr/share/nmap/scripts/ | grep -e "memcached"`
Lets see what it does: `nmap --script-help=memcached-info` run script: `nmap -sS -sV --script=memcached-info -p- -T4 [target IP]` =  Authentication is not required, so theres a potential vulnerability.
![image](https://github.com/user-attachments/assets/2b28a3f1-ba52-48e2-a6a9-8730967c53ac)


### Firewall Detection 

After a common port Scan (Example: `nmap -Pn -sS -F [target IP]`) there always come Not shown Ports back. If `92 *closed* ports` are returned, there is no firewall or filtering active, if `92 *filtered* ports` are returned, there is a firewall or filtering active.
To confirm this, you can run an ACK scan and specify the ports, you know are open. Example: `nmap -Pn -sA -p445,3389 [target IP]`


### IDS evasion and spoofing

One techniques you can use to make it harder for IDS to detect your scan is to fragment your packets into smaller packets. This means that IDS cannot really tell what is going on.

- `-f` to fragment the packets
- Exampe:`nmap -Pn -sS -sV -p80,445,3389 -f [target IP]`
- `--mtu` The Maximum transmission unit allows you to specify the minimum/maximum transfer of bytes to be sent.
- Example: `nmap -Pn -sS -sV -p80,445,3389 -f --mtu [target IP]`
- `--ttl` Set IP time to live field
- `--data-lenght` Append random data to sent packets

On every network wihtin the subnet / network is reserved for the gateway. For that, we need to be connected to the network. With spoofing we make it look like our scans come from the gateway IP. Now if there is a networkadministrator or anotmer net protector it will look like the packets are sent by the gateway IP and it is not as suspicious as when they are sent by a normal client.

- `nmap -Pn -sS -sV -p445,3389 -f --data-length 200 -D [kali linux IP (Gateway)], [target IP]` We can see in Wireshark that the source is the IP from the gateway.
- `nmap -Pn -sS -sV -p445,3389 -f --data-length 200 **-g 53** -D [kali linux IP (Gateway)], [target IP]` We can change the source port to make it look even less suspicious.
