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
#include <sstream>
#include <iomanip>
#include <unistd.h>

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef NETINET_TCP_H

#include <netinet/tcp.h>

#define NETINET_TCP_H
#endif

#define DNS_ANS_TYPE_A          1
#define DNS_ANS_TYPE_NS         2
#define DNS_ANS_TYPE_CNAME      5
#define DNS_ANS_TYPE_SOA        6
#define DNS_ANS_TYPE_PTR        12
#define DNS_ANS_TYPE_MX         15
#define DNS_ANS_TYPE_TXT        16
#define DNS_ANS_TYPE_AAAA       28
#define DNS_ANS_TYPE_SRV        33
#define DNS_ANS_TYPE_DS         43
#define DNS_ANS_TYPE_RRSIG      46
#define DNS_ANS_TYPE_NSEC       47
#define DNS_ANS_TYPE_DNSKEY     48
#define DNS_ANS_TYPE_NSEC3      50
#define DNS_ANS_TYPE_NSEC3PARAM 51
#define DNS_ANS_TYPE_SPF        99

#define NEXTHDR_HOP         0    /* Hop-by-hop option header. */
#define NEXTHDR_IPV6        41    /* IPv6 in IPv6 */
#define NEXTHDR_ROUTING     43    /* Routing header. */
#define NEXTHDR_FRAGMENT    44    /* Fragmentation/reassembly header. */
#define NEXTHDR_AUTH        51    /* Authentication header. */
#define NEXTHDR_DEST        60    /* Destination options header. */
#define NEXTHDR_MOBILITY    135    /* Mobility header. */

#define FOUR_OCTET_UNIT_TO_BYTES    2
#define EIGHT_OCTET_UNIT_TO_BYTES   3
#define UPPER_BYTE_HALF             4
#define IP_HEADER_MIN_LEN           20
#define IPv6_HEADER_LEN             40
#define IP_HEADER_MAX_LEN           60
#define NETWORK_IPv4                4
#define NETWORK_IPv6                6

#define UNUSED(x) (void)(x)

static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                        "abcdefghijklmnopqrstuvwxyz"
                                        "0123456789+/";

class DnsExport {
public:
    DnsExport();

    ~DnsExport();

    std::vector<std::pair<const unsigned char *, const unsigned char **>> tcp_packets;
    std::unordered_map<std::string, int> stats;
    std::vector<int> dns_ids;
    const unsigned char **end_addr;
    size_t datalink_header_length;
    size_t ip_total_len = 0;

    void run(int argc, char **argv);

    void proccess_tcp_packets();

    unsigned char *my_pcap_handler(const unsigned char *packet, bool tcp_parse = false);

private:

    std::string read_name(unsigned char *reader, unsigned char *buffer, unsigned *count);

    void parse_payload(unsigned char *payload, bool tcp);

    std::string
    decode_dns_record(int record_type, unsigned data_length, unsigned *record_length, unsigned char *record_payload,
                      unsigned char *buffer);

    void proccess_next_header(const unsigned char *ipv6_header, uint8_t *next_header, unsigned *offset);

    unsigned char *parse_IPv4_packet(const unsigned char *packet, size_t offset, bool tcp_parse = false);

    unsigned char *parse_IPv6_packet(const unsigned char *packet, size_t offset, bool tcp_parse = false);

    virtual unsigned char *
    parse_transport_protocol(const unsigned char *packet, size_t offset, u_int8_t protocol, bool tcp_parse);

    char *transform_utc_time(uint32_t utc_time);

    std::string proccess_bits_array(unsigned char *record_payload);

    void execute_sniffing(const char *name, bool mode = false);

    std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
};

#endif //DNSEXPORT_H
