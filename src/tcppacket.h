#ifndef TCPPACKET_H
#define TCPPACKET_H

#include <netinet/tcp.h>

#include "constants.h"
#include "misc_utilities.h"

struct TCPPacket {
    TCPPacket();
    TCPPacket(const unsigned int id,
              const unsigned int raw_source, const unsigned int raw_destination,
              const struct tcphdr *header, const string &payload,
              const unsigned int sizeof_payload, const unsigned int sizeof_packet);
    string preview() const;
    void save_to_file() const;
    bool dummy();
    bool is(const TCPPacket& packet) const;
    bool overlaps(const TCPPacket& packet) const;
    bool operator<(const TCPPacket& other) const;
    void operator=(const TCPPacket& packet);
    bool is_syn() const;
    bool is_psh() const;
    bool is_urg() const;
    bool only_ack() const;
    bool is_ack() const;
    bool is_fin() const;
    bool is_rst() const;
    bool acknowledges(const TCPPacket& packet) const;
    bool follows(const TCPPacket& packet) const;
    unsigned int source_port() const;
    unsigned int destination_port() const;
    unsigned long sequence_number() const;
    unsigned long next_sequence_number() const;
    unsigned long acknowledgement_number() const;
    bool connection_start() const;
    void precompute_cache();
    bool similar(TCPPacket& other);
    string summarize_metadata() const;
    double similarity(TCPPacket& other);
    unsigned int id;
    unsigned int raw_source, raw_destination;
    unsigned int sizeof_payload, sizeof_packet;
    ull hashcode;
    struct tcphdr header;
    string payload;
    Dictionary freq;
private:
    string flags_to_string() const;
};


#endif // TCPPACKET_H
