OBJECTS = main.o myIP.o myMAC.o myPcap.o myARP.o
SRCS = main.cpp myIP.cpp myMAC.cpp myPcap.cpp myARP.cpp
LDFLAGS = -lpcap

CFLAGS = -g -c

TARGET = arp_spoof

$(TARGET): $(OBJECTS)
	$(CXX) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

clean:
	rm -f *.o
	rm -f *.txt

  
myIP.o : myARPspoofing.h myIP.cpp
myMAC.o : myARPspoofing.h myMAC.cpp
main.o : myARPspoofing.h main.cpp
myPcap.o:  myARPspoofing.h myPcap.cpp
myARP.o: myARPspoofing.h myARP.cpp