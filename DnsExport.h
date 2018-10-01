#ifndef DNSEXPORT_H
#define DNSEXPORT_H

#include <iostream>
#include <vector>

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
        double time_in_seconds = 60;

        void run(int argc, char **argv);
};

#endif //DNSEXPORT_H
