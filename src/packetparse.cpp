// user-defined libraries
#include "safe_assert.h"
#include "input_preprocessing.h"
#include "packet_filtering.h"

#include "process_packets.h"


int main(int argc, char *argv[]) {

    // parse command line
    string input_filename;
    bool flag_tcp = false, flag_smtp = false, flag_cookies = false;
    assert(parse_command_line(argc, argv, input_filename, flag_tcp, flag_smtp, flag_cookies));

    // read from file into handle
    pcap_t *handle;
    assert(read_input_pcap(input_filename, &handle));

    // verify that physical/link layer is Ethernet
    assert(check_header_type(handle));

    // apply packet filter
    assert(apply_filter(&handle, flag_tcp, flag_smtp, flag_cookies));

    // parse, process, output
    process_packets(handle, flag_tcp, flag_smtp, flag_cookies);


    return 0;
}
