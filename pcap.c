#include "send_arp.h"

int count;

int pcapCapture(struct in_addr* Ip, char* device, pcap_t *pcd, const u_char* packet){
	// get the packet
	int res = 0;
	int flag = 0;
	int *pflag = &flag;
	struct pcap_pkthdr *pkthdr;
    while((res = pcap_next_ex(pcd, &pkthdr, &packet)) >= 0){
        if(res == 0)	continue;
        getVictimMac(((u_char *)&Ip->s_addr), pkthdr, packet, pflag);
        if(flag == 1) break;
    }
	return 1;
}

void getVictimMac(u_char *Ipaddress, const struct pcap_pkthdr *pkthdr, const u_char *packet, int* pflag) {
	// useless: struct in_addr* Ip
    // get ehternet header 
    struct ether_header *eth;   // ethernet header struct
    struct ether_arp *arph;     // arp header struct
    eth = (struct ether_header *)packet;
    FILE *fp = fopen("targetmac.txt", "w");

    // get ARP header   
    packet = packet + sizeof(struct ether_header);

    printf("=============== %04d ===============\n", count);
    count++;
    // if arp
    if(ntohs(eth->ether_type) == ETHERTYPE_ARP){
    	arph = (struct ether_arp *) packet;
        
        printf("\nsource: ");
        for(int i = 0; i<4; i++){
        	printf("%d ", arph->arp_spa[i]);
        }	
        printf("\n");
        for(int i = 0; i<4; i++){
        	printf("%d ", arph->arp_tpa[i]);
        }	
        printf("\n");

        if(strncmp(arph->arp_spa, Ipaddress, 4) == 0){
            printf("Source MAC      : %02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            fprintf(fp, "%02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            *pflag = 1;
            fclose(fp);
            return;
        }
    }
    printf("\n\n");
    fclose(fp);
}