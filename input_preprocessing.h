#ifndef INPUT_PREPROCESSING_H
#define INPUT_PREPROCESSING_H


#include <string>

#include <pcap.h>

#include "constants.h"

bool parse_command_line(int argc, char *argv[], string &input_filename, bool &flag_tcp, bool &flag_smtp, bool &flag_cookies);
bool read_input_pcap(const string &input_filename, pcap_t **handle_pointer);
bool check_header_type(pcap_t *handle);


#endif // INPUT_PREPROCESSING_H
