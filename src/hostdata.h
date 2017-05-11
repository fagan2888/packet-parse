#ifndef HOSTDATA_H
#define HOSTDATA_H


#include <string>

using namespace std;

struct HostData {
    string ip_address;
    unsigned int raw_ip, port_number;
    bool operator==(const HostData& other);
};


#endif // HOSTDATA_H
