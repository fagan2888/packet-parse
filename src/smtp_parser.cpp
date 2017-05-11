#include "misc_utilities.h"
#include "smtp_parser.h"

#include <iostream>
#include <sstream>

string Email::format_sender() {
    return "Sender: " + mail_from + "\n";
}

string Email::format_receiver() {
    return "Receiver: " + rcpt_to + "\n";
}

string Email::format_status() {
    return "Accepted: " + (accepted ? string("yes") : string("no")) + "\n";
}

string Email::output() {
    return format_sender() + "\n" + format_receiver() + "\n" + format_status() + "\n" + data;
}

vector<string> PayloadParser::extract_addresses(const string &prefix) {
    vector<string> addresses;
    istringstream iss(client);
    string line;
    while (getline(iss, line))
        if (begins_with(prefix, line)) {
            size_t offset = prefix.length();
            string address = line.substr(offset);
            if (VERBOSE_DEBUG) clog << "<address line>" << prefix << address << "</address line>" << endl;
            addresses.push_back(address);
        }
    return addresses;
}

vector<string> PayloadParser::extract_data() {
    vector<string> data;
    string temp_data;
    istringstream iss(client);
    string line;
    while (getline(iss, line)) {
        if (begins_with(DATA_PREFIX, line)) {  // found "DATA"
            if (VERBOSE_DEBUG) clog << "<DATA start line>" << line << "</DATA start line>" << endl;
            temp_data = line + "\n";
            continue;
        }
        if (temp_data.empty()) continue;  // not between "DATA" and "."
        temp_data += line;
        if (line != EOD_1)
            temp_data += '\n';
        if (line == EOD_1 || line == EOD_2) {  // found "." or ".\n"
            if (VERBOSE_DEBUG) clog << "<DATA end line>" << line << "</DATA end line>" << endl;
            data.push_back(temp_data);
            temp_data = "";
        }
    }
    return data;
}

vector<bool> PayloadParser::extract_statuses() {
    vector<bool> statuses;
    istringstream iss(server);
    string line;
    while (getline(iss, line))
        if (begins_with(CODE_READY, line)) {
            if (VERBOSE_DEBUG) clog << "<ready>" << line << "</ready>" << endl;
            if (!getline(iss, line)) {
                if (VERBOSE_DEBUG) clog << "</noresponse>" << endl;
                statuses.push_back(false);
                break;
            }
            if (begins_with(CODE_ACCEPTED, line)) {
                if (VERBOSE_DEBUG) clog << "<accepted>" << line << "</accepted>" << endl;
                statuses.push_back(true);
            }
        }
    if (VERBOSE_DEBUG) clog << endl;
    return statuses;
}

PayloadParser::PayloadParser(const string &client, const string &server) {
    this->client = remove_backslash_r(client);
    this->server = remove_backslash_r(server);
    vector<string> sender_addresses = extract_addresses(SENDER_PREFIX);
    vector<string> receiver_addresses = extract_addresses(RECEIVER_PREFIX);
    vector<string> data = extract_data();
    vector<bool> accepted = extract_statuses();

    int n = min(sender_addresses.size(), receiver_addresses.size());
    if (VERBOSE_DEBUG) clog << "Number of messages: " << n << endl;
    emails.reserve(n);
    for (int i = 0; i < n; i++) {
        Email new_email;
        new_email.mail_from = sender_addresses[i];
        new_email.rcpt_to = receiver_addresses[i];
        new_email.data = i < data.size() ? data[i] : "";
        new_email.accepted = i < accepted.size() ? accepted[i] : false;
        emails.push_back(new_email);
        const Email &latest_email = emails.back();
        if (VERBOSE_DEBUG) {
            clog << "Sender: " << latest_email.mail_from << endl;
            clog << "Receiver: " << latest_email.rcpt_to << endl;
            clog << "Accepted: " << (latest_email.accepted ? string("yes") : string("no")) << endl;
            clog << endl;
        }
    }
}

void PayloadParser::write_to_file() {
    int n = emails.size();
    for (int i = 1; i <= n; i++)
        file_output(to_string(i) + ".mail", emails[i-1].output());
}
