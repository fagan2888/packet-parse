OBJECTS := bin/misc_utilities.o bin/smtp_parser.o bin/input_preprocessing.o bin/packet_filtering.o bin/parsing_packets.o bin/tcppacket.o bin/hostdata.o bin/connection.o bin/tcp_flows.o bin/email_traffic.o bin/http_cookies.o bin/process_packets.o

COMPILE := g++ -std=c++11 -lpcap -O3 -c

all: bin/packetparse

clean:
	rm -f $(OBJECTS) bin/packetparse
	rm -f debug/*
	rm -f output/*

install:
	sudo apt-get update
	sudo apt-get install build-essential
	sudo apt-get install g++-4.9
	sudo apt-get install libpcap-dev


bin/misc_utilities.o: src/misc_utilities.cpp src/misc_utilities.h
	$(COMPILE) src/misc_utilities.cpp -o bin/misc_utilities.o

bin/smtp_parser.o: src/smtp_parser.cpp src/smtp_parser.h
	$(COMPILE) src/smtp_parser.cpp -o bin/smtp_parser.o


bin/input_preprocessing.o: src/input_preprocessing.cpp src/input_preprocessing.h
	$(COMPILE) src/input_preprocessing.cpp -o bin/input_preprocessing.o

bin/packet_filtering.o: src/packet_filtering.cpp src/packet_filtering.h
	$(COMPILE) src/packet_filtering.cpp -o bin/packet_filtering.o


bin/parsing_packets.o: src/parsing_packets.cpp src/parsing_packets.h
	$(COMPILE) src/parsing_packets.cpp -o bin/parsing_packets.o


bin/tcppacket.o: src/tcppacket.cpp src/tcppacket.h
	$(COMPILE) src/tcppacket.cpp -o bin/tcppacket.o

bin/hostdata.o: src/hostdata.cpp src/hostdata.h
	$(COMPILE) src/hostdata.cpp -o bin/hostdata.o

bin/connection.o: src/connection.cpp src/connection.h
	$(COMPILE) src/connection.cpp -o bin/connection.o

bin/tcp_flows.o: src/tcp_flows.cpp src/tcp_flows.h
	$(COMPILE) src/tcp_flows.cpp -o bin/tcp_flows.o


bin/email_traffic.o: src/email_traffic.cpp src/email_traffic.h
	$(COMPILE) src/email_traffic.cpp -o bin/email_traffic.o

bin/http_cookies.o: src/http_cookies.cpp src/http_cookies.h
	$(COMPILE) src/http_cookies.cpp -o bin/http_cookies.o


bin/process_packets.o: src/process_packets.cpp src/process_packets.h
	$(COMPILE) src/process_packets.cpp -o bin/process_packets.o


bin/packetparse: src/packetparse.cpp $(OBJECTS)
	g++ -o bin/packetparse src/packetparse.cpp $(OBJECTS) -std=c++11 -lpcap
