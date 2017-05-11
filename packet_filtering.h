#ifndef PACKET_FILTERING_H
#define PACKET_FILTERING_H


#include <string>

#include <pcap.h>


string generate_filter_expression(bool flag_tcp, bool flag_smtp, bool flag_cookies);
bool compile_filter_program(pcap_t **handle_pointer, const string &filter_expression, bpf_program &filter_program);
bool set_filter(pcap_t **handle_pointer, const string& filter_expression, bpf_program &filter_program);
bool apply_filter(pcap_t **handle_pointer, bool flag_tcp, bool flag_smtp, bool flag_cookies);

#endif // PACKET_FILTERING_H
