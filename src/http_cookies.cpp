#include <iostream>

#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include "http_cookies.h"
#include "safe_assert.h"

void preprocess_http(const unsigned int id,
                     const unsigned int raw_source, const unsigned int raw_destination,
                     const string &source_address, const string &destination_address,
                     const unsigned char *packet,
                     const unsigned int &sizeof_header_ethernet,
                     const struct ip *header_internet, const unsigned int &sizeof_header_internet,
                     const unsigned int sizeof_packet,
                     vector<struct TCPPacket> &packet_list) {

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

    clog << '\n';
}

queue<string> extract_cookies(const TCPPacket &packet) {
    queue<string> cookies;

    size_t header_location;
    string remainder = packet.payload;
    while ((header_location = remainder.find(COOKIE_HEADER)) != string::npos) {
        remainder = remainder.substr(header_location);

        size_t colon_location = remainder.find(':');
        size_t equals_location = remainder.find('=');
        size_t semicolon_location = remainder.find(';');

        if (colon_location == string::npos ||
            equals_location == string::npos ||
            semicolon_location == string::npos) continue;

        size_t length_name = equals_location - (colon_location+1);
        size_t length_value = semicolon_location - (equals_location+1);

        string name = trim(remainder.substr(colon_location+1, length_name));
        string value = trim(remainder.substr(equals_location+1, length_value));

        if (name.empty() || value.empty()) continue;

        cookies.push(name + "=" + value);

        remainder = remainder.substr(semicolon_location+1);
    }

    return cookies;
}

void http_cookies(pcap_t *handle_pointer) {
    const unsigned char *packet;
    struct pcap_pkthdr header_packet;

    unsigned int id = 0;
    vector<TCPPacket> packet_list;

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

        preprocess_http(++id,
                        header_internet->ip_src.s_addr, header_internet->ip_dst.s_addr,
                        source_address, destination_address,
                        packet,
                        sizeof_header_ethernet,
                        header_internet, sizeof_header_internet,
                        sizeof_packet,
                        packet_list);
    }
    if (VERBOSE_DEBUG) clog << '\n';

    // process HTTP cookies
    int num_cookies = 0;
    for (const TCPPacket &http_packet : packet_list) {
        queue<string> cookies = extract_cookies(http_packet);
        while (!cookies.empty()) {
            string cookie = cookies.front();
            cookies.pop();
            file_output(to_string(++num_cookies) + ".cookie", cookie);
        }
    }

    clog << "Found " << num_cookies << " cookies\n";
}
