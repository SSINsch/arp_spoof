#include "myARPspoofing.h"
using namespace std;

myMAC::myMAC(){
	int i = 0;
    // broadcastMac initialization
    for(i=0;i<ETHER_ADDR_LEN;i++){
    	broadcastMac.ether_addr_octet[i] = 0xff;
    }
    for(i=0;i<ETHER_ADDR_LEN;i++){
    	zero_fill_mac.ether_addr_octet[i] = 0x00;
    }
}

void myMAC::getMyMac(struct ether_addr *myMac){
	FILE *fp;
	char buf[30] = {0};

	system("ifconfig | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > cmd.txt");
	fp = fopen("cmd.txt", "r");
	if(fp == NULL){
		printf("file open error");
	}
	fgets(buf, sizeof(buf), fp);
	ether_aton_r(buf, myMac);
	fclose(fp);
}
