#ifndef HTTP_COOKIES_H
#define HTTP_COOKIES_H


#include <queue>

#include <netinet/ip.h>
#include <pcap.h>

#include "tcppacket.h"

using namespace std;

void preprocess_http(const unsigned int id,
                     const unsigned int raw_source, const unsigned int raw_destination,
                     const string &source_address, const string &destination_address,
                     const unsigned char *packet,
                     const unsigned int &sizeof_header_ethernet,
                     const struct ip *header_internet, const unsigned int &sizeof_header_internet,
                     const unsigned int sizeof_packet,
                     vector<TCPPacket> &packet_list);

queue<string> extract_cookies(const TCPPacket &packet);

void http_cookies(pcap_t *handle_pointer);


#endif // HTTP_COOKIES_H
