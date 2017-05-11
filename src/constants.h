#ifndef CONSTANTS_H
#define CONSTANTS_H


#include <string>

using namespace std;

extern bool VERBOSE_DEBUG;

constexpr unsigned int ZERO = 0;
typedef unsigned long long ull;
constexpr ull PRIME1 = 786699960817, PRIME2 = 822689925713, PRIME3 = 365128134863;

const string INPUT_FILE_EXTENSION = ".pcap";
const string DEBUG_FOLDER = "debug/";

const string VERBOSITY_FLAG = "-v";
const string TCP_FLAG = "-t";
const string SMTP_FLAG = "-m";
const string COOKIE_FLAG = "-c";

const string FILTER_ALL = "";
const string FILTER_TCP = "tcp";
const string FILTER_SMTP = "tcp && port (25 || 587)";
const string FILTER_HTTP = "tcp port 80";

constexpr int PCAP_INFINITY = -1;
constexpr unsigned int SIZEOF_WORD = sizeof(unsigned int) / sizeof(unsigned char);
constexpr unsigned int CHECKSUM_DECREMENT = 2;
constexpr unsigned int CHECKSUM_SHIFT = 16;

constexpr unsigned int MAX_PREVIEW_SIZE = 100;
constexpr double ERROR_TOLERANCE = 0.1;
constexpr double MINIMUM_SIMILARITY = 1 - ERROR_TOLERANCE;

constexpr unsigned int ZERO_PAYLOAD_INCREMENT = 1;

const string HOST_NICKNAMES[2] = {"initiator", "responder"};
const string WARNING_WRONG_DIRECTION = "Warning: packet with address/port does not belong to this connection";

// client
const string SENDER_PREFIX = "MAIL FROM: ";
const string RECEIVER_PREFIX = "RCPT TO: ";
const string DATA_PREFIX = "DATA";
const string EOD_1 = ".";
const string EOD_2 = ".\n";

// server
const string CODE_READY = "354";
const string CODE_ACCEPTED = "250";

const string COOKIE_HEADER = "Set-Cookie:";

#endif // CONSTANTS_H
