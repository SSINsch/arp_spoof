#include "send_arp.h"

void print_dump(const u_char* packet){
	int start = 0; // starting offset 
	int end = 34; // ending offset

	int i;

	for (i = start & ~15; i < end; i++)
	{
	    if  ((i & 15) == 0) 
	       printf("%04x ",i);
	    printf((i<start)?"   ":"%02x%c",(unsigned char)packet[i],((i+1)&15)?' ':'\n');
	}
	if ((i & 15) != 0)
	    printf("\n");
}

int pcap_from_victiom(struct in_addr *victimIp, struct in_addr *destIp, struct ether_addr *destMac, struct ether_addr *myMac,
						char* device, pcap_t *pcd, struct pcap_pkthdr *pkthdr, const u_char* packet){
	struct ether_header *eth;   // ethernet header struct
    struct ip *iph;				// ip header struct
    const u_char* temp_packet;
    int packet_length = 0;

	eth = (struct ether_header *)packet;
	temp_packet = packet + sizeof(struct ether_header);

	// is it to the dest ip?
	if(ntohs(eth->ether_type) == ETHERTYPE_IP){
		iph = (struct ip *) temp_packet;
		if( ( memcmp( &(iph->ip_dst), &(destIp->s_addr), sizeof(struct in_addr) ) == 0 )
				&& ( memcmp( eth->ether_dhost, myMac->ether_addr_octet, ETHER_ADDR_LEN ) == 0 ) ){
			printf("\n********** FIND: [victim > destination] *********\n");
			print_dump(packet);
			memcpy(eth->ether_dhost, destMac->ether_addr_octet, ETHER_ADDR_LEN);
			print_dump(packet);
			packet_length = pkthdr->len;
			printf("testestsetsetsetsetsetsetsetset    %d            asodijaoisjdoaijsid\n", packet_length);
			if(pcap_sendpacket(pcd, packet, packet_length) == -1)
    			printf("relay pcap_sendpacket error\n");
		}
	}
	
	// if there is no packet captured or [victim > GW](X)
	return 0;
}

int isbroadcast(const u_char* packet, struct in_addr IP){
	struct ether_header *eth;   // ethernet header struct
    struct ether_arp *arph;     // arp header struct
	struct ether_header broad;	// ethernet header struct for broad
	const u_char* temp_packet;

    for(int i=0;i<ETHER_ADDR_LEN;i++)
    	broad.ether_dhost[i] = 0xff;

    eth = (struct ether_header *)packet;
    temp_packet = packet + sizeof(struct ether_header);

    // if arp
    if(ntohs(eth->ether_type) == ETHERTYPE_ARP){
    	arph = (struct ether_arp *) temp_packet;
        // is broadcast?
        if(memcmp(arph->arp_spa, &IP.s_addr, 4) == 0){
            if(memcmp(eth->ether_dhost, broad.ether_dhost, ETHER_ADDR_LEN) == 0){
            	printf("\n********** FIND: broadcast *********\n");
            	return 1;
            }
        }
    }
    return 0;
}