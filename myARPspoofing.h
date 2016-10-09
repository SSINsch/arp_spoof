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
#include "libnet.h"


#define ERRBUF_SIZE			100
#define PACKET_MAX_BYTES	65535
#define PROMISCUOUS_MODE	1
#define NON_PROMISCUOUS		0
#define WAIT_MAX_TIME		1

class myMAC{
public:
	// variable
	struct ether_addr   my_mac_address;
    struct ether_addr	broadcastMac;
    struct ether_addr	zero_fill_mac;
    // function
    myMAC();
	void getMyMac(struct ether_addr *myMac);
};

class myIP{
public:
	// variable
	struct in_addr attacker_ip;
	struct in_addr gateway_ip;
	// function
	void getMyIp(struct in_addr *myIP);
	void getGatewayIp(struct in_addr *GWIp);
};

class myARPheader{
public:
	// variable
	libnet_ethernet_hdr		eth;
	libnet_arp_hdr			arph;
	unsigned char arp_src_mac[ETHER_ADDR_LEN];
	unsigned char arp_src_ip[4];
	unsigned char arp_dst_mac[ETHER_ADDR_LEN];
	unsigned char arp_dst_ip[4];
	// function
	void setARPpacket(struct ether_addr ether_src_mac, struct ether_addr ether_dst_mac,
						struct ether_addr sender_mac, struct in_addr sender_ip,
						struct ether_addr target_mac, struct in_addr target_ip,
						int arp_type, pcap_t *pcd);
};

class myPCAP{
public:
	// variable
	pcap_t 		*pcd;					// packet descriptor
	char 		*device;				// device name
	struct pcap_pkthdr *pkthdr;
	const u_char	*packet;
	// function
	int pcd_init(pcap_t **pcd, char **device);
	void getArpMac(const char *ipaddress, struct ether_addr *victim_mac, int* pflag);
	int pcapCapture(struct in_addr* ip, struct ether_addr *victim_mac);
	void sendARPpacket(myARPheader packet);
	bool isBroadcast(struct in_addr ip);
	void dumpPayload(const u_char *payload, int len);
	int arpSpoofing(myARPheader arph, myIP ip_info, myMAC mac_info, struct in_addr victim_ip, struct ether_addr target_mac);
	int packetRelay(myIP ip_info, myMAC mac_info, struct in_addr victim_ip, struct ether_addr target_mac);
};
