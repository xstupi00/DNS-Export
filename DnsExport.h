#ifndef DNSEXPORT_H
#define DNSEXPORT_H

#include <string>
#include <vector>
#include <netinet/ip6.h>
#include <ctime>
#include <unordered_map>

#include "DataStructures.h"


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
    int time_in_seconds = 60;
    std::vector<const unsigned char*> tcp_packets;
    std::unordered_map<std::string, int> stats;


    void run(int argc, char **argv);

    u_char *my_pcap_handler(const unsigned char *packet, bool tcp_parse);

    u_char *read_name(unsigned char *reader, unsigned char *buffer, int *count);

    void parse_payload(u_char *payload, bool tcp);

    std::string decode_dns_record(int record_type, int data_length, int *record_length, u_char *record_payload, u_char *buffer);

    uint8_t proccess_next_header(const unsigned char* ipv6_header, uint8_t* next_header, unsigned* offset);

    u_char* parse_IPv4_packet(const unsigned char* packet, bool tcp_parse);

    u_char* parse_IPv6_packet(const unsigned char *packet, bool tcp_parse);

    u_char* parse_transport_protocol(const unsigned char* packet, unsigned offset, u_int8_t protocol, bool tcp_parse);

    char* transform_utc_time(const uint32_t utc_time);

    void proccess_tcp_packets();
};

#endif //DNSEXPORT_H
