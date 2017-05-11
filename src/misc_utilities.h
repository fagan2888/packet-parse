#ifndef MISC_UTILITIES_H
#define MISC_UTILITIES_H


#include <unordered_map>
#include <vector>

#include "constants.h"

typedef vector<unsigned int> Counts;

typedef unordered_map<string, unsigned int> Dictionary;

ull generate_hash(const ull &ip1, const ull &ip2, const ull &port1, const ull &port2);

double cosine(const Counts &v1, const Counts &v2);

void populate(const string &s, Dictionary &dict);

void extract_payload(string &payload, const unsigned int sizeof_payload, const unsigned char *source);

bool begins_with(const string &prefix, const string &str);

string remove_backslash_r(const string &str);

string trim(const string &str);

void file_output(const string &filename, const string &output);


#endif // MISC_UTILITIES_H
