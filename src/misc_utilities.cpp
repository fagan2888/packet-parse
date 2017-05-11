#include "misc_utilities.h"

#include <algorithm>
#include <fstream>
#include <cstring>
#include <sstream>

ull generate_hash(const ull &ip1, const ull &ip2, const ull &port1, const ull &port2) {
    ull a = min(ip1, ip2), b = max(ip1, ip2), c = min(port1, port2), d = max(port1, port2);
    return ((a * PRIME1) * PRIME2 + c) * PRIME3 + d;
}

double cosine(const Counts &v1, const Counts &v2) {
    unsigned int dot = inner_product(v1.begin(), v1.end(), v2.begin(), 0);
    unsigned int ss1 = inner_product(v1.begin(), v1.end(), v1.begin(), 0);
    unsigned int ss2 = inner_product(v2.begin(), v2.end(), v2.begin(), 0);
    return sqrt(static_cast<double>(dot*dot) / (ss1 * ss2));
}

void populate(const string &s, Dictionary &dict) {
    istringstream iss(s);
    string word;
    while (iss >> word)
        dict[word]++;
}

void extract_payload(string &payload,
                     const unsigned int sizeof_payload,
                     const unsigned char *source) {
    payload.reserve(sizeof_payload);
    for (int i = 0; i < sizeof_payload; i++)
        payload += source[i];
}

bool begins_with(const string &prefix, const string &str) {
    if (str.length() < prefix.length()) return false;
    return str.substr(0, prefix.length()) == prefix;
}

string remove_backslash_r(const string &str) {
    string clean;
    for (int i = 0; i < str.length(); i++) {
        if (str[i] != '\r') {
            clean += str[i];
            continue;
        }
        clean += '\n';
        char next_char = i+1 < str.length() ? str[i+1] : '\0';
        i += next_char == '\n';
    }
    return clean;
}

string trim(const string &str) {
    string clean;
    size_t first = 0, last = str.length() - 1;
    while (first < str.length() && str[first] == ' ')
        ++first;
    while (last >= 0 && str[last] == ' ')
        --last;
    size_t len = last - first + 1;
    return str.substr(first, len);
}

void file_output(const string &filename, const string &output) {
    ofstream file;
    file.open(OUTPUT_FOLDER + filename);
    file << output;
    file.close();
}
