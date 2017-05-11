#ifndef EMAIL_TRAFFIC_H
#define EMAIL_TRAFFIC_H


#include "tcp_flows.h"

void email_traffic(pcap_t *handle_pointer);

void preprocess_smtp(const unsigned int id,
                     const unsigned int raw_source, const unsigned int raw_destination,
                     const string &source_address, const string &destination_address,
                     const unsigned char *packet,
                     const unsigned int &sizeof_header_ethernet,
                     const struct ip *header_internet, const unsigned int &sizeof_header_internet,
                     const unsigned int sizeof_packet,
                     vector<TCPPacket> &packet_list, Connection &connection);


#endif // EMAIL_TRAFFIC_H
