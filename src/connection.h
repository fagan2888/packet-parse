#ifndef CONNECTION_H
#define CONNECTION_H


#include <unordered_set>
#include <unordered_map>
#include <vector>

#include "tcppacket.h"
#include "hostdata.h"

using namespace std;

typedef unordered_map<unsigned long, unsigned int> frequency;

class Connection {
public:
    Connection();
    Connection(const unsigned int &order,
               const HostData &initiator, const HostData &responder,
               const TCPPacket &packet);
    int direction(const TCPPacket &packet) const;
    void syn_ack(const TCPPacket &packet);
    void bfs_insert(vector<TCPPacket> &packet_list);
    bool check_closed(const TCPPacket& packet);
    void check_acknowledgements();
    void sort_packets();
    void generate_metadata();
    unsigned int count_duplicates(const int dir);
    void output_data();
    void output_emails();
    unsigned int order;
    unsigned long bytes_sent[2];
    string payloads[2];
    TCPPacket lead_packets[2];
    vector<TCPPacket> all_packets[2];
private:
    void print_direction(const unsigned int dir);
    bool is_acked(const TCPPacket& packet);
    bool is_duped(const TCPPacket& packet);
    void filter_duplicates(const int dir);
    unordered_set<unsigned int> acked_ids;
    unordered_set<unsigned int> duplicate;
    HostData metadata[2];
    bool closed;
    void output_meta();
    void output_initiator();
    void output_responder();
    void output_client();
    void output_server();
};


#endif // CONNECTION_H
