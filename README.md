Copyright @lucabotez

# Dataplane Router

## Overview
**Dataplane Router** is an implementation of the **dataplane component** of a router, handling IPv4 packet forwarding using an **optimized Longest Prefix Match (LPM) search**, ARP handling, and ICMP error generation. The router efficiently processes incoming packets, determines the next hop, and ensures packet delivery through a well-structured forwarding mechanism.

## Features
- **IPv4 Packet Forwarding** with efficient **Longest Prefix Match (LPM)**.
- **Optimized Routing Table Lookup** using **binary search**.
- **ARP Protocol Support** (Request, Reply, and Caching).
- **ICMP Error Handling** (Time Exceeded, Destination Unreachable).
- **Packet Queueing** for handling pending packets during ARP resolution.

## Implementation Details
### **1. IPv4 Routing Process**
- Receives an **IPv4 packet** and determines the next hop using an **LPM search** in the routing table.
- If the next hop is found, retrieves the **MAC address** from the **ARP cache** or sends an **ARP request**.
- If the packet's **TTL expires** or no next hop is found, the packet is dropped and an **ICMP error message** is sent.

### **2. Longest Prefix Match (LPM) Optimization**
- The routing table is **sorted** initially by **mask** and **prefix** using **quick sort** (`O(n log n)`).
- A **binary search algorithm** is implemented for fast next-hop lookup.
- If a match is found, the router continues searching among entries with **higher mask values** to get the longest matching prefix.

### **3. ARP Protocol Handling**
#### **3.1 Sending ARP Requests**
- If the MAC address for a next-hop IP is missing, an **ARP request** is broadcasted and the **packet is queued** until a reply is received.

#### **3.2 Receiving ARP Requests**
- If the requested IP matches the router’s interface IP, an **ARP reply** is sent containing the corresponding MAC address.

#### **3.3 Receiving ARP Replies**
- Updates the **ARP cache** with the received **IP-MAC mapping**.
- **Sends all queued packets** waiting for this MAC address.

### **4. ICMP Protocol Handling**
- If the router **receives an ICMP request**, it replies with an **ICMP Echo Reply**.
- If a packet’s **TTL expires**, an **ICMP Time Exceeded** error is sent.
- If no **next hop** is found, an **ICMP Destination Unreachable** message is generated and sent back to the sender.

## Notes
- Uses **low-level packet processing** with direct **ARP and ICMP handling**.
- Implements **binary search** for efficient **next-hop lookup**.
- Supports **queuing packets** when waiting for **ARP resolution**.
- Designed for **high-performance IPv4 routing** on Linux-based environments.
