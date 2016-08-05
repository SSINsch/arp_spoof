#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <string.h>
#include <netinet/in.h> // for ntohs() function
#include <netinet/ip.h>
#include <time.h>


#define ERRBUF_SIZE			100
#define PACKET_MAX_BYTES	2000
#define PROMISCUOUS_MODE	1
#define NON_PROMISCUOUS		0
#define WAIT_MAX_TIME		1


int pcd_init(pcap_t **pcd, char **dev);
void getMyIpMac(struct ether_addr *myMac, struct in_addr *myIp);
void getGWIp(struct in_addr *GWIp);
void ARPreply(struct ether_addr targetMac,	struct in_addr targetIp,
			struct ether_addr fakeMac,	struct in_addr fakeIp,	pcap_t *pcd);
void ARPrequest(struct in_addr targetIp, struct ether_addr senderMac,	struct in_addr senderIp,	pcap_t *pcd);
int pcapCapture(struct in_addr* Ip, char* device, pcap_t *pcd, const u_char* packet);
void getVictimMac(u_char *Ipaddress, const struct pcap_pkthdr *pkthdr, const u_char *packet, int* pflag);
int pcap_from_victiom(struct in_addr *victimIp, struct in_addr *destIp, struct ether_addr *destMac, struct ether_addr *myMac,
						char* device, pcap_t *pcd, struct pcap_pkthdr *pkthdr, const u_char* packet);
int isbroadcast(const u_char* packet, struct in_addr IP);
void print_dump(const u_char* packet);