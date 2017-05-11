#ifndef SMTP_PARSER_H
#define SMTP_PARSER_H

#include <string>
#include <vector>

using namespace std;

class Email {
public:
    string mail_from, rcpt_to;
    string data;
    bool accepted;
    string output();
private:
    string format_sender();
    string format_receiver();
    string format_status();
};

class PayloadParser {
public:
    PayloadParser(const string &client, const string &server);
    void write_to_file();
private:
    vector<Email> emails;
    string client, server;
    vector<string> extract_addresses(const string &prefix);
    vector<string> extract_data();
    vector<bool> extract_statuses();
};


#endif // SMTP_PARSER_H
