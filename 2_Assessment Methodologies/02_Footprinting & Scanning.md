# Footprinting & Scanning

It involves scanning open ports, mapping network topologies, and collecting information about hosts, their operating systems, IP addresses, and user accounts. This gathered data helps to generate a comprehensive technical blueprint of the target organization.

## Networking Fundamentals

### Packets

The primary goal of networking is the exchange information between networked computers; this information is transferred by packets. Packets are nothing but streams of bits running as electric signals on physical media used for data transmission(Ethernet, Wi-Fi etc). These electrical signals are then interpreted as bits (zeros and ones) that make up the information.
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
- Time-to-Live (TTL) - An 8-bit value that indicates the remaining life of the packet.
- Type-of-Service (ToS) - The Type-of-Service field contains an 8-bit binary value that is used to determine the priority of each packet.
- Protocol - This 8-bit value indicated the data payload type that the packet is carrying.


### IPv4 Header Fields


| Field         | Purpose       |
| ------------- | ------------- |
| Version (4 bits)|Indicates the verion of the IP protocol being used. For IPv4, the value is 4.|
| Header Length (4 bits) | Specifies the lenght of the IPv4 in 32-bit words. The minimum value is 5, indication a 60-byte header.  |
| Type of Service (8 bits) | Originally designed for specifiying the quality of service, it includes fields such as Differentiated Services Code Point (DSCP) and Explicit Congestion Notification (ECN) to manage packet priority and congestion control.|
