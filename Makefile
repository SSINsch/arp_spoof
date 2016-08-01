all: arp_spoof

arp_spoof: arp_spoof.o send_arp.o pcap.o main.o
	gcc -g -o arp_spoof arp_spoof.o send_arp.o pcap.o main.o -lpcap

arp_spoof.o: send_arp.h arp_spoof.c
	gcc -g -o arp_spoof.o -c arp_spoof.c
        
send_arp.o: send_arp.h send_arp.c
	gcc -g -o send_arp.o -c send_arp.c

pcap.o: send_arp.h pcap.c
	gcc -g -o pcap.o -c pcap.c

main.o: send_arp.h main.c
	gcc -g -o main.o -c main.c

clean:
	rm -f *.o arp_spoof
	rm -f *.txt
