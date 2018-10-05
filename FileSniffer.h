#ifndef PCAPPARSER_H
#define PCAPPARSER_H

#include <cstring>
#include <iostream>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

#include "DnsExport.h"


struct udphdr {
    u_short	source;
    u_short	dest;
    u_short	length;
    u_short checksum;
};

class FileSniffer: public DnsExport {

    public:
        void parse_pcap_file(const char *pcap_file_name);
};


#endif //PCAPPARSER_H