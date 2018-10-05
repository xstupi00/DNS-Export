#ifndef DNSEXPORT_H
#define DNSEXPORT_H

#include <string>
#include <vector>

#include "DnsStructures.h"


using namespace std;

struct AddressWrapper {
    std::vector<struct sockaddr_in> addr_IPv4;
    std::vector<struct sockaddr_in6> addr_IPv6;
};


class DnsExport {
public:
    DnsExport();

    ~DnsExport();

    std::vector<std::string> pcap_files;
    std::vector<struct AddressWrapper> syslog_server_addr;
    struct AddressWrapper interface_addr;
    std::string interface_name;
    int time_in_seconds = 60;


    void run(int argc, char **argv);

    u_char *my_pcap_handler(const unsigned char *packet);

    u_char *read_name(unsigned char *reader, unsigned char *buffer, int *count);

    void parse_payload(u_char *payload);

    void decode_dns_record(int record_type, int* record_length, u_char* record_payload, u_char* buffer);
};

#endif //DNSEXPORT_H
