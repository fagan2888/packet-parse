#include "connection.h"
#include "constants.h"
#include "safe_assert.h"

#include <algorithm>
#include <fstream>
#include <queue>


Connection::Connection() {
    bytes_sent[0] = bytes_sent[1] = 0;
    closed = false;
}

Connection::Connection(const unsigned int &order,
                       const HostData &initiator, const HostData &responder,
                       const TCPPacket &packet) {
    this->order = order;
    bytes_sent[0] = bytes_sent[1] = 0;
    metadata[0] = initiator;
    metadata[1] = responder;
    lead_packets[0] = packet;
    closed = false;
}

int Connection::direction(const TCPPacket &packet) const {
    struct HostData from = {"", packet.raw_source, packet.source_port()};
    struct HostData to = {"", packet.raw_destination, packet.destination_port()};

    if (from == metadata[0] && to == metadata[1])
        return 0;
    if (from == metadata[1] && to == metadata[0])
        return 1;

    return -1;
}

void Connection::print_direction(const unsigned int dir) {
    if (dir == 0)
        clog << "[initiator -> responder]" << endl;
    else if (dir == 1)
        clog << "[responder -> initiator]" << endl;
    else
        cerr << WARNING_WRONG_DIRECTION << endl;
}

void Connection::syn_ack(const TCPPacket& packet) {
    if (!packet.is_syn()) return;
    int dir = direction(packet);
    if (dir == 1)
        lead_packets[dir] = packet;
}

void Connection::bfs_insert(vector<TCPPacket> &packet_list) {
    const unsigned int n = packet_list.size();
    for (int dir = 0; dir <= 1; dir++) {
        if (VERBOSE_DEBUG) print_direction(dir);
        vector<bool> visited(n);
        queue<TCPPacket*> check;
        check.push(&lead_packets[dir]);
        while (!check.empty()) {
            TCPPacket *from = check.front();
            all_packets[dir].push_back(*from);
            check.pop();
            for (int i = 0; i < n; i++)
                if (!visited[i]) {
                    TCPPacket *to = &packet_list[i];
                    if (to->follows(*from)) {
                        visited[i] = true;
                        check.push(to);
                        if (VERBOSE_DEBUG) clog << from->id << " -?> " << to->id << endl;
                    }
                }
        }
        if (VERBOSE_DEBUG) clog << endl;
    }
    if (VERBOSE_DEBUG) clog << endl;
}

void Connection::check_acknowledgements() {
    for (int dir = 0; dir <= 1; dir++) {
        int rid = 1 - dir;
        if (VERBOSE_DEBUG) print_direction(dir);
        unsigned int num_acked = 0;
        for (const TCPPacket &from : all_packets[dir]) {
            for (const TCPPacket& to : all_packets[rid])
                if (to.acknowledges(from)) {
                    if (VERBOSE_DEBUG) clog << from.id << "<ACK-" << to.id << endl;
                    acked_ids.insert(from.id);
                    num_acked++;
                    goto done;
                }
            done:;
        }
        if (VERBOSE_DEBUG) {
            clog << "acked_packets(" << num_acked << ") <= all_packets(" << all_packets[dir].size() << ")" << endl;
            bool ok = num_acked <= all_packets[dir].size();
            assert(ok);
        }
        if (VERBOSE_DEBUG) clog << endl;
    }
    if (VERBOSE_DEBUG) clog << endl;
}

void Connection::sort_packets() {
    for (int dir = 0; dir <= 1; dir++)
        sort(all_packets[dir].begin(), all_packets[dir].end());
}

bool Connection::check_closed(const TCPPacket& packet) {
    if (closed) return true;
    if (packet.is_ack() && (packet.is_fin() || packet.is_rst())) {
        closed = true;
        return true;
    }
    return false;
}

bool Connection::is_acked(const TCPPacket &packet) {
    return acked_ids.count(packet.id) >= 1;
}

bool Connection::is_duped(const TCPPacket &packet) {
    return duplicate.count(packet.id) >= 1;
}

void Connection::filter_duplicates(const int dir) {
    vector<TCPPacket>& apd = all_packets[dir];
    int n = apd.size();
    payloads[dir] = "";
    for (TCPPacket &packet : apd) {
        if (VERBOSE_DEBUG) clog << "checking duplicates: #" << packet.id << endl;
        for (TCPPacket &dupe : apd) {
            /// if (is_acked(dupe)) continue;
            bool precedes = packet.id < dupe.id, same_acks = dupe.acknowledgement_number() == packet.acknowledgement_number();
            if (precedes && same_acks) {
                bool overlap = dupe.overlaps(packet);
                double similarity = dupe.similarity(packet);
                if (VERBOSE_DEBUG) clog << "against " << packet.id << " (similarity = " << similarity << (overlap ? ", overlapping" : "") << ")" <<  endl;
                if (dupe.similar(packet) && overlap) {
                    if (VERBOSE_DEBUG) clog << packet.id << " retransmitted by " << dupe.id << endl;
                    duplicate.insert(packet.id);
                    break;
                }
            }
        }
        if (/*is_acked(packet) && *////
            !is_duped(packet)) {
            if (VERBOSE_DEBUG) clog << "Appending packet #" << packet.id << "'s payload" << endl;
            payloads[dir] += packet.payload;
        }
    }
}

void Connection::generate_metadata() {
    for (int dir = 0; dir <= 1; dir++) {
        if (VERBOSE_DEBUG) print_direction(dir);
        for (const TCPPacket &packet : all_packets[dir]) {
            bytes_sent[dir] += packet.sizeof_packet;
            check_closed(packet);
        }
        filter_duplicates(dir);
        if (VERBOSE_DEBUG) clog << endl;
    }
}

unsigned int Connection::count_duplicates(const int dir) {
    unsigned int cnt = 0;
    for (const TCPPacket &packet : all_packets[dir])
        cnt += is_duped(packet);
    return cnt;
}

void Connection::output_meta() {
    ofstream metadata_file;
    metadata_file.open(to_string(order) + ".meta");

    metadata_file << "Initiator IP address: " << metadata[0].ip_address << endl;
    metadata_file << "Responder IP address: " << metadata[1].ip_address << endl;

    metadata_file << "Initiator port number: " << metadata[0].port_number << endl;
    metadata_file << "Responder port number: " << metadata[1].port_number << endl;

    metadata_file << "Number of packets sent from initiator to responder: " << all_packets[0].size() << endl;
    metadata_file << "Number of packets sent from responder to initiator: " << all_packets[1].size() << endl;

    metadata_file << "Number of bytes sent from initiator to responder: " << bytes_sent[0] << endl;
    metadata_file << "Number of bytes sent from responder to initiator: " << bytes_sent[1] << endl;

    metadata_file << "Number of duplicate packets sent from initiator to responder: " << count_duplicates(0) << endl;
    metadata_file << "Number of duplicate packets sent from responder to initiator: " << count_duplicates(1) << endl;

    metadata_file << "Closed before EOF was reached: ";
    if (closed)
        metadata_file << "Yes";
    else
        metadata_file << "No";

    metadata_file << endl;
    metadata_file.close();
}

void Connection::output_initiator() {
    file_output(to_string(order) + ".initiator", payloads[0]);
}

void Connection::output_responder() {
    file_output(to_string(order) + ".responder", payloads[1]);
}

void Connection::output_data() {
    output_meta();
    output_initiator();
    output_responder();
}

void Connection::output_client() {
    file_output(DEBUG_FOLDER + to_string(order) + ".client", payloads[0]);
}

void Connection::output_server() {
    file_output(DEBUG_FOLDER + to_string(order) + ".server", payloads[1]);
}

void Connection::output_emails() {
    output_client();
    output_server();
}
