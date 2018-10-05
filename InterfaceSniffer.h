#ifndef INTERFACESNIFFER_H
#define INTERFACESNIFFER_H

#include <cstring>
#include <iostream>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

#include "DnsExport.h"


class InterfaceSniffer: public DnsExport {
    public:
        u_char* unknown_name_interface();

};


#endif //INTERFACESNIFFER_H
