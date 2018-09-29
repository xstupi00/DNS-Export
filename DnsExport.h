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

        std::string pcap_file = "";       ///< name of the pcap file
        struct AddressWrapper syslog_server_addr; ///< ipv4/ipv6/hostname of syslog server
        struct AddressWrapper interface_addr;   ///< name of the network interface
        double time_in_second = 60;       ///< calculation time of statistics

        void run(int argc, char **argv);
};

#endif //DNSEXPORT_H
