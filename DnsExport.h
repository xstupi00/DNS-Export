#ifndef DNSEXPORT_H
#define DNSEXPORT_H

#include <algorithm>
#include <vector>
#include <ctime>
#include <unordered_map>
#include <iomanip>
#include <pcap.h>
#include "ArgumentsParser.h"


class DnsExport {
    public:
        DnsExport();

        ~DnsExport();

        std::vector<const unsigned char*> tcp_packets;
        std::unordered_map<std::string, int> stats;
        std::vector<int> dns_ids;
        const unsigned char **end_addr;


        void run(int argc, char **argv);
        u_char *my_pcap_handler(const unsigned char *packet, bool tcp_parse);
        u_char *read_name(unsigned char *reader, unsigned char *buffer, int *count);
        void parse_payload(u_char *payload, bool tcp);
        std::string decode_dns_record(int record_type, int data_length, int *record_length, u_char *record_payload, u_char *buffer);
        void proccess_next_header(const unsigned char* ipv6_header, uint8_t* next_header, unsigned* offset);
        u_char* parse_IPv4_packet(const unsigned char* packet, bool tcp_parse);
        u_char* parse_IPv6_packet(const unsigned char *packet, bool tcp_parse);
        virtual u_char* parse_transport_protocol(const unsigned char* packet, unsigned offset, u_int8_t protocol, bool tcp_parse);
        char* transform_utc_time(const uint32_t utc_time);
        void proccess_tcp_packets();
        std::stringstream proccess_bits_array(unsigned char *record_payload);
        void sniffing_interface(std::string device_name, double time_in_seconds, std::vector<AddressWrapper> syslog_addr);
        void parse_pcap_file(const char *pcap_file_name);
};

#endif //DNSEXPORT_H
