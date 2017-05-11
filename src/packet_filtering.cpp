#include <iostream>

#include "constants.h"
#include "packet_filtering.h"


string generate_filter_expression(bool flag_tcp, bool flag_smtp, bool flag_cookies) {

    // ETH-IP
    if (!(flag_tcp | flag_smtp | flag_cookies))
        return FILTER_ALL;

    // ETH-IP-TCP
    if (flag_tcp)
        return FILTER_TCP;

    // ETH-IP-TCP-SMTP
    if (flag_smtp)
        return FILTER_SMTP;

    // ETH-IP-TCP-HTTP
    if (flag_cookies)
        return FILTER_HTTP;

    return FILTER_ALL;
}


bool compile_filter_program(pcap_t **handle_pointer, const string &filter_expression, bpf_program &filter_program) {
    if (pcap_compile(*handle_pointer, &filter_program, filter_expression.c_str(), 0, 0) == -1) {
        cerr << "Failed to compile packet filter: " << filter_expression << '\n';
        cerr << pcap_geterr(*handle_pointer);
        return false;
    }

    return true;
}


bool set_filter(pcap_t **handle_pointer, const string &filter_expression, bpf_program &filter_program) {
    if (pcap_setfilter(*handle_pointer, &filter_program) == -1) {
        cout << "Failed to install packet filter: " << filter_expression << '\n';
        cerr << pcap_geterr(*handle_pointer);
        return false;
    }

    return true;
}


bool apply_filter(pcap_t **handle_pointer, bool flag_tcp, bool flag_smtp, bool flag_cookies) {
    string filter_expression = generate_filter_expression(flag_tcp, flag_smtp, flag_cookies);
    struct bpf_program filter_program;

    if (!compile_filter_program(handle_pointer, filter_expression, filter_program))
        return false;

    if (!set_filter(handle_pointer, filter_expression, filter_program))
        return false;

    return true;
}
