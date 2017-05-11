#include <cstring>
#include <fstream>
#include <list>
#include <sstream>

#include <arpa/inet.h>

#include "tcppacket.h"
#include "safe_assert.h"

TCPPacket::TCPPacket() {
    id = -1;
    raw_source = raw_destination = sizeof_payload = sizeof_packet = 0;
    payload = "";
}

TCPPacket::TCPPacket(const unsigned int id,
                     const unsigned int raw_source, const unsigned int raw_destination,
                     const struct tcphdr *header, const string &payload,
                     const unsigned int sizeof_payload, const unsigned int sizeof_packet) {
    this->id = id;
    this->raw_source = raw_source;
    this->raw_destination = raw_destination;
    this->sizeof_payload = sizeof_payload;
    this->sizeof_packet = sizeof_packet;

    this->header = *header;
    this->payload = payload;

    hashcode = generate_hash(raw_source, raw_destination, source_port(), destination_port());

    precompute_cache();
    if (VERBOSE_DEBUG) save_to_file();
}

string TCPPacket::preview() const {
    unsigned int len = min(sizeof_payload, MAX_PREVIEW_SIZE);
    return payload.substr(0, len) + (len < sizeof_payload ? "..." : "");
}

void TCPPacket::save_to_file() const {
    ofstream output_file;
    output_file.open(DEBUG_FOLDER + to_string(id) + ".packet");
    output_file << summarize_metadata() << endl;
    output_file << payload;
    output_file.close();
}

bool TCPPacket::dummy() {
    return raw_source == 0 && raw_destination == 0 && sizeof_payload == 0 && sizeof_packet == 0 && payload.empty();
}

bool TCPPacket::is(const TCPPacket& packet) const {
    return id == packet.id;
}

bool TCPPacket::overlaps(const TCPPacket& packet) const {
    const unsigned int lower_seq = max(sequence_number(), packet.sequence_number());
    const unsigned int upper_seq = min(next_sequence_number(), packet.next_sequence_number());
    return lower_seq < upper_seq;
}

void TCPPacket::operator=(const TCPPacket& packet) {
    id = packet.id;
    raw_source = packet.raw_source;
    raw_destination = packet.raw_destination;
    sizeof_payload = packet.sizeof_payload;
    sizeof_packet = packet.sizeof_payload;
    hashcode = packet.hashcode;
    header = packet.header;
    payload = packet.payload;
}

bool TCPPacket::operator<(const TCPPacket& other) const {
    unsigned long ack = acknowledgement_number(), other_ack = other.acknowledgement_number();
    if (ack != other_ack) return ack < other_ack;
    unsigned long seq = sequence_number(), other_seq = other.sequence_number();
    if (seq != other_seq) return seq < other_seq;
    unsigned long next_seq = next_sequence_number(), other_next_seq = other.next_sequence_number();
    if (next_seq != other_next_seq) return next_seq < other_next_seq;
    return sizeof_payload < other.sizeof_payload;
}

bool TCPPacket::is_syn() const {
    return header.th_flags & TH_SYN;
}

bool TCPPacket::is_psh() const {
    return header.th_flags & TH_PUSH;
}

bool TCPPacket::is_urg() const {
    return header.th_flags & TH_URG;
}

bool TCPPacket::is_ack() const {
    return header.th_flags & TH_ACK;
}

bool TCPPacket::only_ack() const {
    return header.th_flags == TH_ACK;
}

bool TCPPacket::is_fin() const {
    return header.th_flags & TH_FIN;
}

bool TCPPacket::is_rst() const {
    return header.th_flags & TH_RST;
}

bool TCPPacket::acknowledges(const TCPPacket& packet) const {
    return acknowledgement_number() == packet.next_sequence_number();
}

bool TCPPacket::follows(const TCPPacket& predecessor) const {
    return sequence_number() == predecessor.next_sequence_number();
}

unsigned int TCPPacket::source_port() const {
    return ntohs(header.th_sport);
}

unsigned int TCPPacket::destination_port() const {
    return ntohs(header.th_dport);
}

unsigned long TCPPacket::sequence_number() const {
    return ntohl(header.th_seq);
}

unsigned long TCPPacket::next_sequence_number() const {
    unsigned int minimum_increment = only_ack() ? 0 : ZERO_PAYLOAD_INCREMENT;
    unsigned int increment = max(minimum_increment, sizeof_payload);
    return sequence_number() + increment;
}

unsigned long TCPPacket::acknowledgement_number() const {
    return ntohl(header.th_ack);
}

bool TCPPacket::connection_start() const {
    if (!is_syn() && acknowledgement_number() == 0)
        cerr << "Warning: non-SYN packet with acknowledgement number 0" << endl;
    return is_syn() && acknowledgement_number() == 0;
}

void TCPPacket::precompute_cache() {
    if (sizeof_payload == 0) return;
    if (!freq.empty()) return;
    populate(payload, freq);
}

double TCPPacket::similarity(TCPPacket& other) {
    double length = min(sizeof_payload, other.sizeof_payload);
    if (!length) return 0;
    Dictionary &freq1 = freq, &freq2 = other.freq;
    Dictionary lexicon = freq1;
    for (auto record : freq2)
        lexicon[record.first]++;
    int n = lexicon.size();
    Counts v1(n), v2(n);
    int i = 0;
    for (auto record : lexicon) {
        const string &word = record.first;
        v1[i] = freq1[word];
        v2[i] = freq2[word];
        i++;
    }
    return cosine(v1, v2);
}

bool TCPPacket::similar(TCPPacket& other) {
    return similarity(other) >= MINIMUM_SIMILARITY;
}

string TCPPacket::flags_to_string() const {
    string output;
    list<pair<bool, string>> flags = {
        {is_syn(), "SYN"},
        {is_psh(), "PSH"},
        {is_urg(), "URG"},
        {is_fin(), "FIN"},
        {is_rst(), "RST"},
        {is_ack(), "ACK"},
    };
    bool mult = flags.front().first;
    if (mult) output += flags.front().second;
    for (auto f = flags.begin(); (++f) != flags.end();)
        if (f->first) {
            output += (mult ? "-" : "") + f->second;
            mult = true;
        }
    return output;
}

string TCPPacket::summarize_metadata() const {
    ostringstream oss;
    oss << "TCP packet #: " << id << endl;
    oss << "TCP source port: " << source_port() << endl;
    oss << "TCP destination port: " << destination_port() << endl;
    oss << "Sequence number: " << sequence_number() << endl;
    oss << "Next sequence number: " << next_sequence_number() << endl;
    oss << "Acknowledgement number: " << acknowledgement_number() << endl;
    oss << flags_to_string() << endl;
    oss << "Payload size: " << sizeof_payload << " bytes" << endl;
    oss << "Number of bytes sent: " << sizeof_packet << endl;
    return oss.str();
}
