#include <cstring>
#include <iostream>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "constants.h"
#include "parsing_packets.h"


void print_hexadecimal(const unsigned char* pointer, const unsigned int sizeof_data) {
    for (int i = 0; i < sizeof_data/2; i++) {
        if (i)
            printf(" ");
        printf("%02x%02x", *pointer, *(pointer+1));
        pointer += 2;
    }
    printf("\n");
}

char *format_address_mac(const u_int8_t address_host[]) {

    static char zero_padded[2*6+5];
    sprintf(zero_padded, "%02x:%02x:%02x:%02x:%02x:%02x",
            (unsigned) address_host[0],
            (unsigned) address_host[1],
            (unsigned) address_host[2],
            (unsigned) address_host[3],
            (unsigned) address_host[4],
            (unsigned) address_host[5]);

    return zero_padded;
}

PseudoHeader *initialize_pseudoheader(const struct ip *header_internet, const unsigned int protocol, const int sizeof_header_internet) {
    static PseudoHeader pseudoheader;

    pseudoheader.address_source = header_internet->ip_src;
    pseudoheader.address_destination = header_internet->ip_dst;
    pseudoheader.reserved_zeroes = 0;
    pseudoheader.protocol = protocol;
    pseudoheader.length = htons(ntohs(header_internet->ip_len) - sizeof_header_internet);

    return &pseudoheader;
}

unsigned short checksum(unsigned short *bytestream, const unsigned int sizeof_checksum_data, const int checksum_tcp) {

    int sum = -checksum_tcp, remainder;
    for (remainder = sizeof_checksum_data; remainder >= CHECKSUM_DECREMENT; remainder -= CHECKSUM_DECREMENT) {
        sum += *bytestream;
        bytestream++;
    }

    if (remainder == 1)
        sum += *((unsigned char*) bytestream);

    sum = (sum >> CHECKSUM_SHIFT) + (sum & 0xffff);
    sum += (sum >> CHECKSUM_SHIFT);

    return ~sum;
}

void report_packet_type(const struct ip &header_internet, unsigned int &protocol, PacketCounter &counter) {
    cout << "Packet type: ";

    protocol = header_internet.ip_p;
    switch (protocol) {
        case IPPROTO_TCP: {
            counter.tcp++;
            cout << "TCP";
            break;
        }
        case IPPROTO_UDP: {
            counter.udp++;
            cout << "UDP";
            break;
        }
        default: {
            counter.other++;
            cout << "other";
            break;
        }
    }

    cout << endl;
}

void report_metadata_tcp(const unsigned char *packet, const unsigned int &protocol,
                         const struct ether_header *header_ethernet, const unsigned int &sizeof_header_ethernet,
                         const struct ip *header_internet, const unsigned int &sizeof_header_internet,
                         unsigned int &sizeof_payload) {
    const struct tcphdr *header_tcp = (struct tcphdr*) (packet + sizeof_header_ethernet + sizeof_header_internet);
    const unsigned int sizeof_header_tcp = header_tcp->th_off * SIZEOF_WORD;

    cout << "TCP source port: " << ntohs(header_tcp->th_sport) << endl;
    cout << "TCP destination port: " << ntohs(header_tcp->th_dport) << endl;

    unsigned char *payload = (unsigned char *) (packet + sizeof_header_ethernet + sizeof_header_internet + sizeof_header_tcp);
    sizeof_payload = ntohs(header_internet->ip_len) - sizeof_header_internet - sizeof_header_tcp;

    const struct PseudoHeader *pseudoheader = initialize_pseudoheader(header_internet, protocol, sizeof_header_internet);
    const unsigned int sizeof_pseudoheader = sizeof(struct PseudoHeader);

    const unsigned int sizeof_checksum_data = sizeof_pseudoheader + sizeof_header_tcp + sizeof_payload;
    unsigned char* checksum_data = (unsigned char*) malloc(sizeof_checksum_data);
    memcpy(checksum_data, pseudoheader, sizeof_pseudoheader);
    memcpy(checksum_data+sizeof_pseudoheader, header_tcp, sizeof_header_tcp);
    memcpy(checksum_data+sizeof_pseudoheader+sizeof_header_tcp, payload, sizeof_payload);

    unsigned int checksum_tcp = ntohs(header_tcp->th_sum);
    unsigned short checksum_calculated = ntohs(checksum((unsigned short*) checksum_data, sizeof_checksum_data, header_tcp->th_sum));
    cout << "TCP checksum: " << checksum_tcp << (checksum_tcp == checksum_calculated ? " (valid)" : " (invalid)") << endl;
    cout << "Calculated checksum: " << checksum_calculated << endl;

    free(checksum_data);

    cout << "Payload size: " << sizeof_payload << " bytes" << endl;
}

void report_metadata_udp(const unsigned char *packet,
                         const unsigned int &sizeof_header_ethernet,
                         const struct ip *header_internet, const unsigned int &sizeof_header_internet,
                         unsigned int &sizeof_payload) {
    const struct udphdr *header_udp = (struct udphdr*) (packet + sizeof_header_ethernet + sizeof_header_internet);
    const unsigned int sizeof_header_udp = sizeof(struct udphdr);

    cout << "UDP source port: " << ntohs(header_udp->uh_sport) << endl;
    cout << "UDP destination port: " << ntohs(header_udp->uh_dport) << endl;

    unsigned char *payload = (unsigned char *) (packet + sizeof_header_ethernet + sizeof_header_internet + sizeof_header_udp);
    sizeof_payload = ntohs(header_internet->ip_len) - sizeof_header_internet - sizeof_header_udp;

    cout << "Payload size: " << sizeof_payload << " bytes" << endl;
}

void parsing_packets(pcap_t *handle_pointer) {
    const unsigned char *packet;
    PacketCounter counter = {0, 0, 0, 0};
    unsigned int packet_number = 0;
    struct pcap_pkthdr header_packet;

    while ((packet = pcap_next(handle_pointer, &header_packet)) != NULL) {
        cout << "#" << ++packet_number << endl;

        const struct ether_header *header_ethernet = (struct ether_header*) packet;
        const unsigned int sizeof_header_ethernet = sizeof(struct ether_header);

        const struct ip *header_internet = (struct ip*) (packet + sizeof_header_ethernet);
        const unsigned int sizeof_header_internet = header_internet->ip_hl * SIZEOF_WORD;

        unsigned int protocol = 0;
        report_packet_type(*header_internet, protocol, counter);

        cout << "Source MAC address: " << format_address_mac(header_ethernet->ether_shost) << endl;
        cout << "Destination MAC address: " << format_address_mac(header_ethernet->ether_dhost) << endl;

        cout << "Source IP address: " << inet_ntoa(header_internet->ip_src) << endl;
        cout << "Destination IP address: " << inet_ntoa(header_internet->ip_dst) << endl;

        unsigned int sizeof_payload = ntohs(header_internet->ip_len) - sizeof_header_internet;  // default (other)

        if (protocol == IPPROTO_TCP) {
            report_metadata_tcp(packet, protocol,
                                header_ethernet, sizeof_header_ethernet,
                                header_internet, sizeof_header_internet,
                                sizeof_payload);
        }

        if (protocol == IPPROTO_UDP) {
            report_metadata_udp(packet,
                                sizeof_header_ethernet,
                                header_internet, sizeof_header_internet,
                                sizeof_payload);
        }

        cout << endl;
    }

    cout << endl;
    counter.total = counter.tcp + counter.udp + counter.other;
    cout << "Total number of packets processed: " << counter.total << endl;
    cout << "TDP packets: " << counter.tcp << endl;
    cout << "UDP packets: " << counter.udp << endl;
    cout << "Non-TCP/UDP packets: " << counter.other << endl;

    cout << endl;
}
