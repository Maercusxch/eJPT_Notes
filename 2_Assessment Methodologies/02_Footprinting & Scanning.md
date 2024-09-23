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

