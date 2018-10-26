#ifndef DNSEXPORT_H
#define DNSEXPORT_H

#include <algorithm>
#include <vector>
#include <ctime>
#include <unordered_map>
#include <pcap.h>
#include "ArgumentsParser.h"
#include <iostream>
#include <csignal>
#include <cmath>

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef NETINET_TCP_H
#include <netinet/tcp.h>
#define NETINET_TCP_H
#endif


class DnsExport {
public:
    DnsExport();

    ~DnsExport();

    std::vector<std::pair<const unsigned char *, const unsigned char **>> tcp_packets;
    std::unordered_map<std::string, int> stats;
    std::vector<int> dns_ids;
    const unsigned char **end_addr;


    void run(int argc, char **argv);

    unsigned char *my_pcap_handler(const unsigned char *packet, bool tcp_parse);

    unsigned char *read_name(unsigned char *reader, unsigned char *buffer, unsigned *count);

    void parse_payload(unsigned char *payload, bool tcp);

    std::string
    decode_dns_record(int record_type, unsigned data_length, unsigned *record_length, unsigned char *record_payload,
                      unsigned char *buffer);

    void proccess_next_header(const unsigned char *ipv6_header, uint8_t *next_header, unsigned *offset);

    unsigned char *parse_IPv4_packet(const unsigned char *packet, bool tcp_parse);

    unsigned char *parse_IPv6_packet(const unsigned char *packet, bool tcp_parse);

    virtual unsigned char *
    parse_transport_protocol(const unsigned char *packet, unsigned offset, u_int8_t protocol, bool tcp_parse);

    char *transform_utc_time(const uint32_t utc_time);

    void proccess_tcp_packets();

    std::string proccess_bits_array(unsigned char *record_payload);

    void sniffing_interface(std::string device_name, double time_in_seconds, std::vector<AddressWrapper> syslog_addr);

    void parse_pcap_file(const char *pcap_file_name);
};

#endif //DNSEXPORT_H
