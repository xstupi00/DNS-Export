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
#include <netinet/tcp.h>

#include "DnsExport.h"

using namespace std;

class TCPReassembler: public DnsExport
{
    public:
        TCPReassembler();
        ~TCPReassembler();

        uint16_t tcp_segment_length = 0;
        uint32_t tcp_sequence_number;
        uint16_t dns_length;
        uint16_t summary_length = 0;
        uint32_t last_packet_length = 0;

        std::vector<const unsigned char*> reassembling_packets(std::vector<const unsigned char*> tcp_packets);
        u_char* parse_IPv4_tcp_packet(const unsigned char* packet, bool compare);
        u_char* parse_IPv6_tcp_packet(const unsigned char *packet, bool compare);
        u_char* parse_tcp_protocol(const unsigned char* packet, unsigned offset, u_int8_t protocol, uint16_t total, bool compare);
};

#endif //TCPREASSEMBLER_H