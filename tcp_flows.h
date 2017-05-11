#ifndef TCP_FLOWS_H
#define TCP_FLOWS_H


#include <list>
#include <unordered_map>

#include <pcap.h>

#include "tcppacket.h"
#include "connection.h"

using namespace std;

void preprocess_tcp(const unsigned int id,
                    const unsigned int raw_source, const unsigned int raw_destination,
                    const string &source_address, const string &destination_address,
                    const unsigned char *packet,
                    const unsigned int &sizeof_header_ethernet,
                    const struct ip *header_internet, const unsigned int &sizeof_header_internet,
                    const unsigned int sizeof_packet,
                    unordered_map<ull, vector<TCPPacket>>& packet_lists,
                    unordered_map<ull, list<Connection>>& connections, unsigned int &order,
                    vector<ull> &hashcodes);

void syn_ack(Connection &connection, const vector<TCPPacket> &packet_list);

bool handshake_completed(Connection &connection, const vector<TCPPacket> &packet_list);

void tcp_flows(pcap_t *handle_pointer);


#endif // TCP_FLOWS_H
