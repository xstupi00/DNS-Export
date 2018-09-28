//
// Created by Simon Stupinsky on 28/09/2018.
//

#ifndef DNSEXPORT_H
#define DNSEXPORT_H

#include <string>
#include <netinet/in.h>

using namespace std;


class DnsExport {
    public:
        DnsExport();
        ~DnsExport();

        std::string pcap_file = "";       ///< name of the pcap file
        struct sockaddr_in6 syslog_server_addr;  ///< IPv6 variant
        std::string interface;   ///< name of the network interface
        double time_in_second = 60;       ///< calculation time of statistics

        void run(int argc, char **argv);
};


#endif //DNSEXPORT_H
