#ifndef PCAPPARSER_H
#define PCAPPARSER_H

#include <cstring>
#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include "DnsExport.h"

void my_pcap_handler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

struct udphdr {
    u_short	source;
    u_short	dest;
    u_short	length;
    u_short checksum;
};

class PcapParser: public DnsExport {

    public:
        void parse_pcap_file();
};


#endif //PCAPPARSER_H