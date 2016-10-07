#include "myARPspoofing.h"

void myARPheader::setARPpacket(struct ether_addr ether_src_mac, struct ether_addr ether_dst_mac,
							struct ether_addr sender_mac, struct in_addr sender_ip,
							struct ether_addr target_mac, struct in_addr target_ip,
							int arp_type, pcap_t *pcd){
	const int ETHER_hdrlen = sizeof(struct libnet_ethernet_hdr);
	const int ARP_hdrlen = sizeof(struct libnet_arp_hdr);
	u_char packet[ETHER_hdrlen + ARP_hdrlen];		// packet

	// ethernet header setting
	eth.ether_type = htons(ETHERTYPE_ARP);
	memcpy(eth.ether_shost, &ether_src_mac.ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(eth.ether_dhost, &ether_dst_mac.ether_addr_octet, ETHER_ADDR_LEN);
    
	// arp header setting
	arph.ar_hrd = htons(ARPHRD_ETHER);
	arph.ar_pro = htons(ETHERTYPE_IP);
	arph.ar_hln = ETHER_ADDR_LEN;
	arph.ar_pln = 4;
	arph.ar_op = htons(arp_type);
	// arp header setting (variable in the class)
	memcpy(arp_src_mac, &sender_mac.ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(arp_dst_mac, &target_mac.ether_addr_octet, ETHER_ADDR_LEN);
	memcpy(arp_src_ip, &sender_ip, 4);
	memcpy(arp_dst_ip, &target_ip, 4);
}
