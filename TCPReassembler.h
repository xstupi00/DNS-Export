#ifndef TCPREASSEMBLER_H
#define TCPREASSEMBLER_H

#include <arpa/inet.h>
#include <cstring>
#include <getopt.h>
#include <ifaddrs.h>
#include <iostream>
#include <netdb.h>
#include <net/if.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <vector>
#include <iomanip>

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef NETINET_TCP_H
#include <netinet/tcp.h>
#define NETINET_TCP_H
#endif

#include "DnsExport.h"

using namespace std;

class TCPReassembler : public DnsExport {
public:
    TCPReassembler(int link_type);

    ~TCPReassembler();

    size_t tcp_segment_length = 0;
    unsigned int tcp_sequence_number;
    size_t dns_length;
    size_t summary_length = 0;
    size_t last_packet_length = 0;
    size_t packet_hdr_len = 0;

    std::vector<std::pair<const unsigned char *, const unsigned char **>>
    reassembling_packets(std::vector<std::pair<const unsigned char *, const unsigned char **>> tcp_packets);

    unsigned char *
    parse_transport_protocol(const unsigned char *packet, size_t offset, u_int8_t protocol, bool tcp_parse) override;
};

#endif //TCPREASSEMBLER_H
