#include "parsing_packets.h"
#include "tcp_flows.h"
#include "email_traffic.h"
#include "http_cookies.h"
#include "process_packets.h"


void process_packets(pcap_t *handle_pointer, bool flag_tcp, bool flag_smtp, bool flag_cookies) {

    // ETH-IP
    if (!(flag_tcp | flag_smtp | flag_cookies))
        parsing_packets(handle_pointer);

    // ETH-IP-TCP
    if (flag_tcp)
        tcp_flows(handle_pointer);

    // ETH-IP-TCP-SMTP
    if (flag_smtp)
        email_traffic(handle_pointer);

    // ETH-IP-TCP-HTTP
    if (flag_cookies)
        http_cookies(handle_pointer);
}
