#include "myARPspoofing.h"
using namespace std;

void myIP::getMyIp(struct in_addr *myIP){
	FILE *fp;
	char buf[30] = {0};

	system("ifconfig ens33 | awk '/inet addr/ {gsub(\"addr:\", \"\", $2); print $2}' > cmd.txt");
	fp = fopen("cmd.txt", "r");
	if(fp == NULL){
		printf("file open error");
	}
	fgets(buf, sizeof(buf), fp);
	buf[strlen(buf) - 1] = 0;
	inet_pton(AF_INET, buf, &(myIP->s_addr));
	fclose(fp);
}

void myIP::getGatewayIp(struct in_addr *gwIP){
	FILE *fp;
	char buf[20] = {0};
	system("ip route show default | awk '/default/ {print $3}' > cmd.txt");
	fp = fopen("cmd.txt", "r");
	if(fp == NULL){
		printf("file open error");
	}
	fgets(buf, sizeof(buf), fp);
	buf[strlen(buf) - 1] = 0;
	inet_pton(AF_INET, buf, &(gwIP->s_addr));
	fclose(fp);
}