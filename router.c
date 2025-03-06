// Copyright @lucabotez

#include "queue.h"
#include "lib.h"
#include "protocols.h"

// the routing table and its length
struct route_table_entry *rtable;
int rtable_len;

// the arp cache and its length
struct arp_table_entry *arp_cache;
int arp_cache_len;

// struct used when enqueueing packets in the waiting queue
struct queue_packet {
	char buf[MAX_PACKET_LEN]; // packet data
	int interface; // destination interface
	uint32_t next_hop; // destination ip address
	size_t len; // packet size
};

// function used by the qsort(), sorts the routing table in
// descending order by the mask and the prefix
int cmp_func(const void *a, const void *b) {
	struct route_table_entry *entry_a = (struct route_table_entry *)a;
	struct route_table_entry *entry_b = (struct route_table_entry *)b;

	if (entry_a->mask != entry_b->mask) 
		return entry_b->mask - entry_a->mask;

	return entry_b->prefix - entry_a->prefix;
}

// binary search algorithm implementation for finding
// the desired routing table entry index
int binary_search(uint32_t ip_dest) {
	int fst = 0, lst = rtable_len;
	while (fst <= lst) {
		int middle = fst + (lst - fst) / 2;
		uint32_t res = ip_dest & rtable[middle].mask;

		// we compare the result (ip_addr & mask) with the
		// rtable entry prefix
		if (res == rtable[middle].prefix)
			return middle;

		if (res < rtable[middle].prefix) {
			fst = middle + 1;
			continue;
		}

		lst = middle - 1;
	}

	// if we cannot find a valid entry
	return -1;
}

// gets the longest matching prefix by finding a prefix with the
// binary search algorithm and looking only at entries with a
// larger mask
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	int index = binary_search(ip_dest);

	// if no matching prefix was found return NULL
	if (index == -1)
		return NULL;

	struct route_table_entry *route = &rtable[index];

	// search only the entries with larger masks
	for (int i = index; i >= 0; i--)
		if (rtable[i].prefix == (ip_dest & rtable[i].mask))
			route = &rtable[i];

	// pointer to the needed route table entry
	return route;
}

// searches the arp cache by a given ip address, if found returns
// a pointer to the arp cache entry
struct arp_table_entry *get_cached_mac(uint32_t ip_dest) {
	for (int i = 0; i < arp_cache_len; i++) {
		if (arp_cache[i].ip == ip_dest) {
			return &arp_cache[i];
		}
	}

	// if the ip address cannot be found return NULL
	return NULL;	
}

// the function handles the icmp packet sending process based on
// the icmp packet type (0 -> reply, 3 -> destination unreachable,
// 11 -> time exceeded)
void send_icmp(char *buf, size_t len, int interface, int type) {
	// pointer to the ip header of the received packet
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// new icmp packet
	char new_buf[MAX_PACKET_LEN];

	struct ether_header *new_eth_hdr = (struct ether_header *) new_buf;
	struct iphdr *new_ip_hdr = (struct iphdr *) 
							   (new_buf + sizeof(struct ether_header));
	struct icmphdr *new_icmp_hdr = (struct icmphdr *)
								   (new_buf + sizeof(struct ether_header)
	 									    + sizeof(struct iphdr));

	// set the values for the ethernet header
	struct route_table_entry *icmp_matched_route = get_best_route(ip_hdr->saddr);
	struct arp_table_entry *icmp_matched_cache = 
							get_cached_mac(icmp_matched_route->next_hop);

	get_interface_mac(interface, new_eth_hdr->ether_shost);
	memcpy(new_eth_hdr->ether_dhost, icmp_matched_cache->mac, 6);
	new_eth_hdr->ether_type = htons(ETHERTYPE_IP);

	// copy the ip header of the old packet and modify the required fields
	memcpy(new_ip_hdr, ip_hdr, sizeof(struct iphdr));

	new_ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	new_ip_hdr->daddr = ip_hdr->saddr;
	new_ip_hdr->protocol = IP_ICMP;

	// set the values for the icmp header
	new_icmp_hdr->code = 0;
	new_icmp_hdr->type = type; // given type when calling the function
	new_icmp_hdr->checksum = 0; // preparationn for calculating the checksum

	// icmp error case, we have to send a larger packet that includes the
	// old ip header + 64 bits of data
	if (type != 0) {
		// update the ip header total len
		new_ip_hdr->tot_len = htons(2 * sizeof(struct iphdr)
									  + sizeof(struct icmphdr) + 8);

		// reset the header ttl (with the standard ipv4 ttl value)
		new_ip_hdr->ttl = 64;

		// calculate the new checksum
		new_ip_hdr->check = 0;
		new_ip_hdr->check = htons(checksum((uint16_t *) new_ip_hdr,
								  sizeof(struct iphdr)));

		// add the new data (ip header + 64 bits)
		memcpy(new_icmp_hdr + sizeof(struct icmphdr), ip_hdr,
			   sizeof(struct iphdr) + 8);

		// calculate the icmp header checksum
		new_icmp_hdr->checksum = htons(checksum((uint16_t *) new_icmp_hdr, 
												sizeof(struct icmphdr)
												+ sizeof(struct iphdr)
												+ 8));

		// send the packet
		send_to_link(icmp_matched_route->interface, new_buf,
					 sizeof(struct ether_header) + 2 * sizeof(struct iphdr)
												 + sizeof(struct icmphdr) + 8);
		return;
	}

	// icmp reply case, only the checksum and total len have to be updated
	new_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	new_ip_hdr->check = 0;
	new_ip_hdr->check = htons(checksum((uint16_t *)new_ip_hdr,
							  sizeof(struct iphdr)));

	// send the packet
	send_to_link(icmp_matched_route->interface, new_buf, len);

	return;
}

// helper function that assigns the needed values to a
// given arp header
void init_arp(struct arp_header *arp_hdr, int op) {
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(ETHERTYPE_IP);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(op);
}

int main(int argc, char *argv[]) {
	// default values for the null and broadcast addresses
	uint8_t broadcast_mac_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint8_t null_addr[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    char buf[MAX_PACKET_LEN];

    init(argc - 2, argv + 2);

	// initialise the routing table 
	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	DIE(rtable == NULL, "Not enough memory to allocate the routing table.");

	// initialise the arp cache
	arp_cache = malloc(sizeof(struct arp_table_entry) * 50);
	DIE(arp_cache == NULL, "Not enough memory to allocate the arp cache.");

	// load the routing table
    rtable_len = read_rtable(argv[1], rtable);
    arp_cache_len = 0;

	// sort the routing table using the cmp_func
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), cmp_func);

	// initialise the waiting queue
	queue waiting_queue = queue_create();
	DIE(waiting_queue == NULL, "Not enough memory to allocate the queue.");

    while (1) {
        int interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// pointer to the ethernet header of the packet
        struct ether_header *eth_hdr = (struct ether_header *) buf;

		// the received packet is an arp one
		if (eth_hdr->ether_type == htons(ETHERTYPE_ARP)) {
			// pointer to the arp header of the packet
			struct arp_header *arp_hdr = (struct arp_header *)
										 (buf + sizeof(struct ether_header));

			switch (ntohs(arp_hdr->op)) {
				// arp request case
				case 1:
					// ignore the packet if the ip does not match
					if (arp_hdr->tpa != inet_addr(get_interface_ip(interface)))
						continue;

					// create a new arp packet
					char arp_buf[MAX_PACKET_LEN];
					struct ether_header *new_eth_hdr = (struct ether_header *)
													   arp_buf;
					struct arp_header *new_arp_hdr = (struct arp_header *)
													 (arp_buf + sizeof(struct ether_header));

					// set up the values for the arp header
					memcpy(new_arp_hdr->tha, arp_hdr->sha, 6);
					get_interface_mac(interface, new_arp_hdr->sha);

					new_arp_hdr->spa = arp_hdr->tpa;
					new_arp_hdr->tpa = arp_hdr->spa;

					init_arp(new_arp_hdr, 2);

					// set up the values for the ethernet header
					get_interface_mac(interface, new_eth_hdr->ether_shost);
					memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
					new_eth_hdr->ether_type = htons(ETHERTYPE_ARP);

					// get the interface for the target ip address
					struct route_table_entry *matched_route = get_best_route(new_arp_hdr->tpa);

					// send the packet
					send_to_link(matched_route->interface, arp_buf,
								 sizeof(struct ether_header)
								 + sizeof(struct arp_header));
					continue;
				
				// arp reply case
				case 2:
					// add the newly found mac address with its matching ip address
					// in the arp cache
					arp_cache[arp_cache_len].ip = arp_hdr->spa;
					memcpy(arp_cache[arp_cache_len].mac, arp_hdr->sha, 6);

					// increase the cache len
					arp_cache_len++;

					// iterate through the waiting queue to send the packets
					// to the newly found mac address
					queue aux_queue = queue_create();
					while (!queue_empty(waiting_queue)) {
						struct queue_packet *qp = (struct queue_packet *)
												  queue_deq(waiting_queue);

						// if the packet next hop does not match the newly found one
						// add the packet in the auxiliary queue and skip to the next
						// iteration
						if (qp->next_hop != arp_cache[arp_cache_len - 1].ip) {
							queue_enq(aux_queue, qp);
							continue;
						}

						// extract the pointer to the ethernet header of the packet
						struct ether_header *unsent_eth_hdr = (struct ether_header *)
															  qp->buf;

						// update the destination addres with the found one
						memcpy(unsent_eth_hdr->ether_dhost,
							   arp_cache[arp_cache_len - 1].mac, 6);

						// send the packet
						send_to_link(qp->interface, qp->buf, qp->len);
					}

					// put the unsent packets back in the waiting queue
					while (!queue_empty(aux_queue))
						queue_enq(waiting_queue, queue_deq(aux_queue));

					free(aux_queue);
					continue;

				default:
					break;
			}
		}

		// the received packet is an ip one
		if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {
			// pointer to the ip header of the packet
            struct iphdr *ip_hdr = (struct iphdr *)
								   (buf + sizeof(struct ether_header));

			// check if the packet is an ICMP request packet
			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
				send_icmp(buf, len, interface, 0);
				continue;
			}

			uint16_t check_copy = ntohs(ip_hdr->check);
			ip_hdr->check = 0;

			// verify the checksum
			if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != check_copy)
				continue;

			// update the ttl, check if the packet time expired
			ip_hdr->ttl--;
			if (ip_hdr->ttl < 1) {
				send_icmp(buf, len, interface, 11);
				continue;
			}

			struct route_table_entry *matched_route = get_best_route(ip_hdr->daddr);

			// check if a next hop was found for the packet
			if (!matched_route || matched_route->next_hop == 0) {
				send_icmp(buf, len, interface, 3);
				continue;
			}

			// update the checksum
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr,
								  sizeof(struct iphdr)));

			// add the current mac address to the cache
			if (!get_cached_mac(inet_addr(get_interface_ip(interface)))) {
				arp_cache[arp_cache_len].ip = inet_addr(get_interface_ip(interface));
				get_interface_mac(interface, arp_cache[arp_cache_len].mac);
				arp_cache_len++;
			}

			// check if the next hop has the mac address in the cache
			struct arp_table_entry *matched_cache_entry = get_cached_mac(matched_route->next_hop);
			if (matched_cache_entry) {
				// set up the values for the ethernet header
				get_interface_mac(interface, eth_hdr->ether_shost);
				memcpy(eth_hdr->ether_dhost, matched_cache_entry->mac, 6);

				//
				send_to_link(matched_route->interface, buf, len);
				continue;
			}

			// if a mac address hasn't been found, add the ip packet to
			// the waiting queue and send an arp request on the network

			// create a queue packet entry
			struct queue_packet qp;
			memcpy(qp.buf, buf, len);
			qp.interface = matched_route->interface;
			qp.len = len;
			qp.next_hop = matched_route->next_hop;

			// enqueue the packet
			queue_enq(waiting_queue, &qp);

			// create the arp request packet
			char new_buf[MAX_PACKET_LEN];
			struct ether_header *new_eth_hdr = (struct ether_header *) new_buf;
			struct arp_header *new_arp_hdr = (struct arp_header *)
											 (new_buf + sizeof(struct ether_header));
			
			// set up the values for the ethernet header
			get_interface_mac(matched_route->interface, new_eth_hdr->ether_shost);

			// send to the entire network
			memcpy(new_eth_hdr->ether_dhost, broadcast_mac_addr, 6);
			new_eth_hdr->ether_type = htons(ETHERTYPE_ARP);

			// set up the values for the arp header
			init_arp(new_arp_hdr, 1);
			get_interface_mac(matched_route->interface, new_arp_hdr->sha);
			memcpy(new_arp_hdr->tha, null_addr, 6);

			new_arp_hdr->spa = inet_addr(get_interface_ip(interface));
			new_arp_hdr->tpa = matched_route->next_hop;

			// send the arp packet
            send_to_link(matched_route->interface, new_buf,
						 sizeof(struct ether_header) + sizeof(struct arp_header));
        }
    }
}
