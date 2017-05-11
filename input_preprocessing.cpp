#include <iostream>

#include <pcap.h>

#include "constants.h"
#include "input_preprocessing.h"

bool VERBOSE_DEBUG = false;

bool parse_command_line(int argc, char *argv[], string &input_filename, bool &flag_tcp, bool &flag_smtp, bool &flag_cookies) {

    // command line flags
    for (int i = 0; i < argc; i++) {
        string argument(argv[i]);
        VERBOSE_DEBUG |= (argument == VERBOSITY_FLAG);
        flag_tcp |= (argument == TCP_FLAG);
        flag_smtp |= (argument == SMTP_FLAG);
        flag_cookies |= (argument == COOKIE_FLAG);
        if (argument.rfind(INPUT_FILE_EXTENSION) + INPUT_FILE_EXTENSION.length() == argument.length()) {
            if (!input_filename.empty()) {
                cerr << "Please specify only one pcap file as input." << endl;
                return false;
            }
            input_filename = argument;
        }
    }

    // check input file specification
    if (input_filename.empty()) {
        cerr << "Usage: " << argv[0] << " {input.pcap}" << endl;
        return false;
    }

    return true;
}


bool read_input_pcap(const string &input_filename, pcap_t **handle_pointer) {
    char errbuf[PCAP_ERRBUF_SIZE];
    *handle_pointer = pcap_open_offline(input_filename.c_str(), errbuf);

    if (*handle_pointer == NULL) {
        cerr << "Cannot process pcap file " << input_filename << ": " << errbuf << endl;
        return false;
    }

    return true;
}


bool check_header_type(pcap_t *handle) {
    int header_type = pcap_datalink(handle);

    if (header_type != DLT_EN10MB) {
        cerr << "Unable to handle header type " << pcap_datalink_val_to_name(header_type);
        cerr << " (" << pcap_datalink_val_to_description(header_type) << ")" << endl;
        return false;
    }

    return true;
}
