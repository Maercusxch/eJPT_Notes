# Footprinting & Scanning


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


Transpost Layer Protocols

- **TCP** (Transmission Control Protocol): Connection-oriented protocol providing reliable and ordered delivery of data.
- **UDP** (User Datagram Protocol): Connectionless protocol that is faster but provides no guarantees regarding the order or reliability of data delivery.


### TCP

TCP is one of the main protocols operating at the Transport Layer (Layer 4) of the OSI model. TCP is a connection oriented, reliable protocol that provides a dependable and ordered delivery of data between two devices over a network. It ensures, that data sent from one application on a device is recieved accurately and in the correct order by another application on a different device.

#### TCP characteristics

Connection-Oriented:
-  TCP establishes a connection between the sender and receiver before any data is exchanged. This connection is a virtual circuit that ensures reliable and ordered data transfer.
Reliability:
- TCP guarantees reliable delivery of data. It achieves this through mechanisms such as acknowledgements (ACK) and retransmissions of lost or corrupted packets. If a segment of data is not acknowledged. TCP automatically resends the segment.
Ordered Data Transfer:
- TCP ensures that data is delivered in the correct order. If segments of data arrive out of order, TCP reorders them before passing them to the higher-layer application.
