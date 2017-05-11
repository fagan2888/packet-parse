#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <unordered_map>

#include "safe_assert.h"
#include "tcp_flows.h"

using namespace std;

void preprocess_tcp(const unsigned int id,
                    const unsigned int raw_source, const unsigned int raw_destination,
                    const string &source_address, const string &destination_address,
                    const unsigned char *packet,
                    const unsigned int &sizeof_header_ethernet,
                    const struct ip *header_internet, const unsigned int &sizeof_header_internet,
                    const unsigned int sizeof_packet,
                    unordered_map<ull, vector<struct TCPPacket>>& packet_lists,
                    unordered_map<ull, list<struct Connection>>& connections, unsigned int &order,
                    vector<ull> &hashcodes) {

    const struct tcphdr *header_tcp = (struct tcphdr*) (packet + sizeof_header_ethernet + sizeof_header_internet);
    const unsigned int sizeof_header_tcp = header_tcp->th_off * SIZEOF_WORD;


    const unsigned int sizeof_payload = ntohs(header_internet->ip_len) - sizeof_header_internet - sizeof_header_tcp;
    const unsigned char *payload_source = packet + sizeof_header_ethernet + sizeof_header_internet + sizeof_header_tcp;
    string payload;
    extract_payload(payload, sizeof_payload, payload_source);

    TCPPacket packet_tcp(id, raw_source, raw_destination, header_tcp, payload, sizeof_payload, sizeof_packet);

    clog << packet_tcp.summarize_metadata();
    if (VERBOSE_DEBUG) {
        clog << "<payload>" << endl;
        clog << packet_tcp.payload << endl;
        clog << "</payload>" << endl;
    }

    packet_lists[packet_tcp.hashcode].push_back(packet_tcp);
    if (VERBOSE_DEBUG) clog << "hashcheck(" << packet_tcp.hashcode << "): " << packet_lists[packet_tcp.hashcode].size() << endl;

    if (packet_tcp.connection_start()) {
        ++order;
        if (VERBOSE_DEBUG) clog << "total number of connections opened so far: " << order << endl;

        hashcodes.push_back(packet_tcp.hashcode);
        if (VERBOSE_DEBUG) assert(order == hashcodes.size());

        HostData initiator = {source_address, raw_source, packet_tcp.source_port()};
        HostData responder = {destination_address, raw_destination, packet_tcp.destination_port()};
        Connection new_connection(order, initiator, responder, packet_tcp);
        connections[packet_tcp.hashcode].push_back(new_connection);
    }

    clog << endl;
}

void syn_ack(Connection &connection, const vector<TCPPacket> &packet_list) {
    for (const TCPPacket& packet : packet_list)
        if (packet.is_syn() && packet.is_ack()) {
            if (VERBOSE_DEBUG) assert(connection.lead_packets[1].dummy());
            connection.lead_packets[1] = packet;
        }
}

bool handshake_completed(Connection &connection, const vector<TCPPacket> &packet_list) {
    const TCPPacket &synack_packet = connection.lead_packets[1];
    for (const TCPPacket& packet : packet_list)
        if (packet.acknowledges(synack_packet))
            return true;
    return false;
}

void tcp_flows(pcap_t *handle_pointer) {
    const unsigned char *packet;
    struct pcap_pkthdr header_packet;

    unsigned int id = 0;
    unsigned int order = 0;
    unordered_map<ull, vector<TCPPacket>> packet_lists;
    unordered_map<ull, list<Connection>> connections;
    vector<ull> hashcodes = {0};

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
        clog << "Source IP address: " << source_address << endl;
        clog << "Destination IP address: " << destination_address << endl;

        unsigned int sizeof_packet = ntohs(header_internet->ip_len) - sizeof_header_internet;

        preprocess_tcp(++id,
                       header_internet->ip_src.s_addr, header_internet->ip_dst.s_addr,
                       source_address, destination_address,
                       packet,
                       sizeof_header_ethernet,
                       header_internet, sizeof_header_internet,
                       sizeof_packet,
                       packet_lists,
                       connections, order, hashcodes);
    }
    if (VERBOSE_DEBUG) clog << endl;

    // check handshakes
    for (int i = 1; i <= order; i++) {
        const ull hashcode = hashcodes[i];
        const vector<TCPPacket> &packet_list = packet_lists[hashcode];
        list<Connection> &hashed_connections = connections[hashcode];
        for (auto iter = hashed_connections.begin(); iter != hashed_connections.end(); iter++) {
            Connection& connection = (*iter);
            if (VERBOSE_DEBUG) assert(!connection.lead_packets[0].dummy());
            syn_ack(connection, packet_list);
            if (connection.lead_packets[1].dummy() || !handshake_completed(connection, packet_list)) {
                if (VERBOSE_DEBUG) clog << "Found broken handshake (no SYN-ACK)!" << endl;
                swap(hashcodes[i], hashcodes[order]);
                packet_lists.erase(hashcode);
                iter = hashed_connections.erase(iter);
                iter--;
                order--;
            } else if (VERBOSE_DEBUG) clog << "handshake " << order << " successful" << endl;
        }
    }

    // add packets to connection streams, check for ACKs
    for (int i = 1; i <= order; i++) {
        const ull hashcode = hashcodes[i];
        for (Connection &connection : connections[hashcode]) {
            connection.bfs_insert(packet_lists[hashcode]);
            connection.check_acknowledgements();
            connection.sort_packets();
            connection.generate_metadata();
            connection.output_data();
        }
        if (VERBOSE_DEBUG) clog << endl;
    }
}

