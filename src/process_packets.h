#ifndef PROCESS_PACKETS_H
#define PROCESS_PACKETS_H


#include <pcap.h>


void process_packets(pcap_t *handle_pointer, bool flag_tcp, bool flag_smtp, bool flag_cookies);


#endif // PROCESS_PACKETS_H
