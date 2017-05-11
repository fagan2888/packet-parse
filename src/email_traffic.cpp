#include <iostream>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include "email_traffic.h"
#include "misc_utilities.h"
#include "safe_assert.h"
#include "smtp_parser.h"

void preprocess_smtp(const unsigned int id,
                     const unsigned int raw_source, const unsigned int raw_destination,
                     const string &source_address, const string &destination_address,
                     const unsigned char *packet,
                     const unsigned int &sizeof_header_ethernet,
                     const struct ip *header_internet, const unsigned int &sizeof_header_internet,
                     const unsigned int sizeof_packet,
                     vector<struct TCPPacket> &packet_list, Connection &connection) {

    const struct tcphdr *header_tcp = (struct tcphdr*) (packet + sizeof_header_ethernet + sizeof_header_internet);
    const unsigned int sizeof_header_tcp = header_tcp->th_off * SIZEOF_WORD;

    const unsigned int sizeof_payload = ntohs(header_internet->ip_len) - sizeof_header_internet - sizeof_header_tcp;
    const unsigned char *payload_source = packet + sizeof_header_ethernet + sizeof_header_internet + sizeof_header_tcp;
    string payload;
    extract_payload(payload, sizeof_payload, payload_source);

    TCPPacket packet_tcp(id, raw_source, raw_destination, header_tcp, payload, sizeof_payload, sizeof_packet);

    clog << packet_tcp.summarize_metadata();
    if (VERBOSE_DEBUG) {
        clog << "<payload>\n";
        clog << packet_tcp.payload << '\n';
        clog << "</payload>\n";
    }

    packet_list.push_back(packet_tcp);

    if (packet_tcp.connection_start()) {
        if (VERBOSE_DEBUG) clog << "Opened a connection.\n";

        HostData initiator = {source_address, raw_source, packet_tcp.source_port()};
        HostData responder = {destination_address, raw_destination, packet_tcp.destination_port()};
        connection = Connection(1, initiator, responder, packet_tcp);
    }

    clog << '\n';
}

void email_traffic(pcap_t *handle_pointer) {
    const unsigned char *packet;
    struct pcap_pkthdr header_packet;

    unsigned int id = 0;
    vector<TCPPacket> packet_list;
    Connection connection;

    // read packets into memory, open connections
    while ((packet = pcap_next(handle_pointer, &header_packet)) != NULL) {

        const struct ether_header *header_ethernet = (struct ether_header*) packet;
        const unsigned int sizeof_header_ethernet = sizeof(struct ether_header);

        const struct ip *header_internet = (struct ip*) (packet + sizeof_header_ethernet);
        const unsigned int sizeof_header_internet = header_internet->ip_hl * SIZEOF_WORD;
        const unsigned int protocol = header_internet->ip_p;

        assert(protocol == IPPROTO_TCP);

        const string source_address(inet_ntoa(header_internet->ip_src));
        const string destination_address(inet_ntoa(header_internet->ip_dst));
        clog << "Source IP address: " << source_address << '\n';
        clog << "Destination IP address: " << destination_address << '\n';

        unsigned int sizeof_packet = ntohs(header_internet->ip_len) - sizeof_header_internet;

        preprocess_smtp(++id,
                        header_internet->ip_src.s_addr, header_internet->ip_dst.s_addr,
                        source_address, destination_address,
                        packet,
                        sizeof_header_ethernet,
                        header_internet, sizeof_header_internet,
                        sizeof_packet,
                        packet_list,
                        connection);
    }
    if (VERBOSE_DEBUG) clog << '\n';

    // check handshakes
    if (VERBOSE_DEBUG) assert(!connection.lead_packets[0].dummy());
    syn_ack(connection, packet_list);
    if (connection.lead_packets[1].dummy() || !handshake_completed(connection, packet_list)) {
        if (VERBOSE_DEBUG) clog << "Found broken handshake (no SYN-ACK)!\n";
    } else if (VERBOSE_DEBUG) clog << "handshake successful\n";

    // add packets to connection streams, check for ACKs
    connection.bfs_insert(packet_list);
    connection.check_acknowledgements();
    connection.sort_packets();
    connection.generate_metadata();
    connection.output_data();
    if (VERBOSE_DEBUG) clog << '\n';

    // intermediate debug data
    connection.output_emails();

    // write smtp data to output
    PayloadParser parser(connection.payloads[0], connection.payloads[1]);
    parser.write_to_file();
}
