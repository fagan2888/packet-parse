#ifndef PARSING_PACKETS_H
#define PARSING_PACKETS_H


#include <netinet/in.h>
#include <pcap.h>

void print_hexadecimal(const unsigned char* pointer, const unsigned int sizeof_data);

struct PacketCounter {
    int tcp, udp, other;
    int total;
};

char *format_address_mac(const u_int8_t address_host[]);

void parsing_packets(pcap_t *handle_pointer);

struct PseudoHeader {
    struct in_addr address_source, address_destination;
    unsigned char reserved_zeroes, protocol;
    unsigned short length;
};

PseudoHeader *initialize_pseudoheader(const struct ip *header_internet, const unsigned int protocol, const int sizeof_header_internet);

unsigned short checksum(unsigned short *bytestream, const unsigned int sizeof_checksum_data, const int checksum_tcp);

void report_metadata_tcp(const unsigned char *packet, const unsigned int &protocol,
                         const struct ether_header *header_ethernet, const unsigned int &sizeof_header_ethernet,
                         const struct ip *header_internet, const unsigned int &sizeof_header_internet,
                         unsigned int &sizeof_payload);

void report_metadata_udp(const unsigned char *packet,
                         const unsigned int &sizeof_header_ethernet,
                         const struct ip *header_internet, const unsigned int &sizeof_header_internet,
                         unsigned int &sizeof_payload);

void parsing_packets(pcap_t *handle_pointer);


#endif // PARSING_PACKETS_H
