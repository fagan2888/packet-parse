OBJECTS := misc_utilities.o smtp_parser.o input_preprocessing.o packet_filtering.o parsing_packets.o tcppacket.o hostdata.o connection.o tcp_flows.o email_traffic.o http_cookies.o process_packets.o

COMPILE := g++ -std=c++11 -lpcap -c


all: packetparse;

clean:
	rm -f $(OBJECTS) packetparse

install:
	sudo apt-get update
	sudo apt-get install build-essential
	sudo apt-get install g++-4.9
	sudo apt-get install libpcap-dev


misc_utilities.o: misc_utilities.cpp misc_utilities.h
	$(COMPILE) misc_utilities.cpp

smtp_parser.o: smtp_parser.cpp smtp_parser.h
	$(COMPILE) smtp_parser.cpp


input_preprocessing.o: input_preprocessing.cpp input_preprocessing.h
	$(COMPILE) input_preprocessing.cpp

packet_filtering.o: packet_filtering.cpp packet_filtering.h
	$(COMPILE) packet_filtering.cpp


parsing_packets.o: parsing_packets.cpp parsing_packets.h
	$(COMPILE) parsing_packets.cpp


tcppacket.o: tcppacket.cpp tcppacket.h
	$(COMPILE) tcppacket.cpp

hostdata.o: hostdata.cpp hostdata.h
	$(COMPILE) hostdata.cpp

connection.o: connection.cpp connection.h
	$(COMPILE) connection.cpp

tcp_flows.o: tcp_flows.cpp tcp_flows.h
	$(COMPILE) tcp_flows.cpp


email_traffic.o: email_traffic.cpp email_traffic.h
	$(COMPILE) email_traffic.cpp

http_cookies.o: http_cookies.cpp http_cookies.h
	$(COMPILE) http_cookies.cpp


process_packets.o: process_packets.cpp process_packets.h
	$(COMPILE) process_packets.cpp


packetparse: packetparse.cpp $(OBJECTS)
	g++ -o packetparse packetparse.cpp $(OBJECTS) -std=c++11 -lpcap
