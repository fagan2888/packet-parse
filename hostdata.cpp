#include "hostdata.h"

bool HostData::operator==(const HostData& other) {
    return (raw_ip == other.raw_ip) && (port_number == other.port_number);
}
