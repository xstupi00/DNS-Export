/**************************************************************
 * Project:     DNS Export
 * File:		DnsExport.cpp
 * Author:		Šimon Stupinský
 * University: 	Brno University of Technology
 * Faculty: 	Faculty of Information Technology
 * Course:	    Network Applications and Network Administration
 * Date:		28.09.2018
 * Last change:	16.11.2018
 *
 * Subscribe:	The module of DnsExport class, that represents the main logic of whole application
 *
 **************************************************************/

/**
 * @file    DnsExport.cpp
 * @brief   This module contains methods that executing the main logic of processing packets.
 */

#include "DnsExport.h"
#include "TCPReassembler.h"
#include "SyslogSender.h"
#include "Base32Encoder.h"

///< global variables for access to it in thsignal handler

///< interval for sending the syslog messages
unsigned time_in_seconds;
///< vector of syslog servers name where will be sending the statistics obtaining by this application
std::vector<std::string> syslog_servers;
///< stats of frequency of the individual DNS answers mapping to the unordered map
std::unordered_map<std::string, int> stats;

/**
* Default Contructor.
*/
DnsExport::DnsExport() = default;


/**
* Destructor.
*/
DnsExport::~DnsExport() = default;


void DnsExport::execute_sniffing(const char *name, bool mode) {
    char err_buff[PCAP_ERRBUF_SIZE];    ///< Error string
    const unsigned char *packet;        ///< Caught packet
    struct pcap_pkthdr header;          ///< Handled packet by pcap module for obtaining the datalink header length
    struct bpf_program fp;              ///< The compiled filter expression
    char filter_exp[] = "port 53";      ///< The filter expression
    pcap_t *handle;                     ///< handle for sniffing the packets

    ///< Open the session in promiscuous mode -  online or offline sniffing
    handle = mode ? pcap_open_live(name, BUFSIZ, 1, 1000, err_buff) : pcap_open_offline(name, err_buff);
    if (handle != nullptr) {
        ///< compile the filter
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) != -1) {
            ///< set the filter to the packet capture handle
            if (pcap_setfilter(handle, &fp) != -1) {
                ///< obtains the datalink header length
                this->datalink_header_length = get_length_of_datalink(pcap_datalink(handle));
                if ((int)this->datalink_header_length == -1) {
                    std::cerr << "Invalid type of datalink header!" << std::endl;
                    exit(EXIT_FAILURE);
                }
                for (;;) { ///< infinite loop for sniffing on the given network interface
                    ///< loop for processing the caught packets - one by one
                    while ((packet = pcap_next(handle, &header)) != nullptr) {
                        ///< store the pointer to the end of caught packet
                        this->end_addr = std::addressof(packet) + header.caplen;
                        ///< parsing the layers headers (link, network and transport)
                        u_char *payload = this->my_pcap_handler(packet);
                        if (payload) {
                            ///< parse DNS Payload
                            this->parse_payload(payload, false);
                        }
                    }
                    ///< end for loop in the case of offline sniffing (whole file was readed)
                    if (!mode) break;
                }
            } else {    ///< pcap_setfilter() failed
                std::perror("pcap_setfilter() failed:");
                exit(EXIT_FAILURE);
            }
        } else {        ///< pcap_compile() failed
            std::perror("pcap_compile() failed:");
            exit(EXIT_FAILURE);
        }
    } else {            ///< pcap_open() failed
        std::perror(mode ? "pcap_open_live() failed:" : "pcap_open_offline() failed:");
        exit(EXIT_FAILURE);
    }
    ///< close the packet handler
    pcap_close(handle);
}

std::string DnsExport::read_name(unsigned char *reader, unsigned char *buffer, unsigned *count) {
    std::string name;
    bool jumped = false;
    *count = 1;

    for (; *reader and std::addressof(reader) <= (unsigned char **) this->end_addr; reader++) {
        if (*reader >= 192) {   ///< pointer to another bytes in the packet
            ///< check correct access to the memory
            if (std::addressof(reader) + sizeof(unsigned char) <= (unsigned char **) this->end_addr) {
                ///< computing the pointer offset and set it to valid value, where have to read in next run of loop
                reader = buffer + (((*reader) << 8) + *(reader + 1) - 0xc000) - 1;
                ///< stop the counting of shifting bytes in the actual position of pointer in the packet
                jumped = true;
            } else { ///< invalid access to the memory
                break;
            }
        } else { ///< reading and store the readed char
            name.push_back(*reader);
        }

        ///< count the shifting bytes in the actual position of pointer (compression is only 2 bytes)
        if (!jumped) (*count)++;
    }

    ///< addition the second byte in the case of DNS compression
    if (jumped) (*count)++;

    ///< backward transformation domain name from the DNS form - 3www6google3com0 to www.google.com
    for (unsigned i = 0; i < name.length(); i++) {
        try {
            auto label_length = (unsigned) name.at(i);
            name.insert(name.at(i) + i + 1, ".");
            name.erase(i, 1);
            i += label_length;
        } catch (const std::out_of_range &oor) {
            break;
        }
    }
    try { ///< try remove the lat dot in the obtained name
        name.erase(name.length() - 1);
    } catch (const std::out_of_range &oor) {
        ///< catch exceptions std::out_of_range
    }

    ///< if the domain_name was empty will be given by <ROOT> else stay without change
    return (*reader ? "-" : (name.empty() ? "<ROOT>" : name));
}

///< encode given bytes to the format base_64 (see header file for the closer information)
std::string DnsExport::base64_encode(unsigned char const *bytes_to_encode, unsigned int in_len) {
    std::string ret;
    int i = 0, j = 0;
    unsigned char char_array_3[3], char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';

    }

    return (ret.empty() ? "-" : ret);
}


void DnsExport::proccess_next_header(const unsigned char *ipv6_header, uint8_t *next_header, unsigned *offset) {
    ///< selection the actual type of IPv6 Extension Header
    switch (*next_header) {
        case NEXTHDR_FRAGMENT: {    ///< Fragment Header
            ///< check correct access to the memory from that will be reading
            if (std::addressof(ipv6_header) + *offset + sizeof(struct ip6_frag) <= this->end_addr) {
                ///< obtaining the IPv6 Fragment Header
                auto ipv6_frag = (struct ip6_frag *) (ipv6_header + *offset);
                ///< set the offset according to length of IPv6 Fragment Header
                *offset += sizeof(struct ip6_frag);
                ///< set the next header for following processing after the return from the this method
                *next_header = ipv6_frag->ip6f_nxt;
            } else {    ///< invalid access to the memory, packet will be ignored
                *offset = 0;
            }
            break;
        }
        case NEXTHDR_DEST: {        ///< Destination Options
            ///< check correct access to the memory from that will be reading
            if (std::addressof(ipv6_header) + *offset + sizeof(struct ipv6_dest) <= this->end_addr) {
                ///< obtaining the IPv6 Destination Options
                auto ipv6_dest = (struct ipv6_dest *) (ipv6_header + *offset);
                ///< set the offset according to length of IPv6 Destination Options
                *offset += (ipv6_dest->ip6d_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_dest);
                ///< set the next header for following processing after the return from the this method
                *next_header = ipv6_dest->ip6d_nxt;
            } else {    ///< invalid access to the memory, packet will be ignored
                *offset = 0;
            }
            break;
        }
        case NEXTHDR_HOP: {         ///< Hop-By-Hop Options
            ///< check correct access to the memory from that will be reading
            if (std::addressof(ipv6_header) + *offset + sizeof(struct ipv6_hbh) <= this->end_addr) {
                ///< obtaining the IPv6 Hop-By-Hop Options
                auto ipv6_hop_hdr = (struct ipv6_hbh *) (ipv6_header + *offset);
                ///< set the offset according to length of IPv6 Hop-By-Hop Options
                *offset += (ipv6_hop_hdr->ip6h_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_hbh);
                ///< set the next header for following processing after the return from the this method
                *next_header = ipv6_hop_hdr->ip6h_nxt;
            } else {    ///< invalid access to the memory, packet will be ignored
                *offset = 0;
            }
            break;
        }
        case NEXTHDR_ROUTING: {     ///< Routing Header
            ///< check correct access to the memory from that will be reading
            if (std::addressof(ipv6_header) + *offset + sizeof(struct ipv6_rthdr) <= this->end_addr) {
                ///< obtaining the IPv6 Rounting Header
                auto ipv6_rthdr = (struct ipv6_rthdr *) (ipv6_header + *offset);
                ///< set the offset according to length of IPv6 Routing Header
                *offset += (ipv6_rthdr->ip6r_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_rthdr);
                ///< set the next header for following processing after the return from the this method
                *next_header = ipv6_rthdr->ip6r_nxt;
            } else {    ///< invalid access to the memory, packet will be ignored
                *offset = 0;
            }
            break;
        }
        case NEXTHDR_AUTH: {        ///< Authentication Header
            ///< check correct access to the memory from that will be reading
            if (std::addressof(ipv6_header) + *offset + sizeof(struct auth_hdr) <= this->end_addr) {
                ///< obtaining the IPv6 Authentication Header
                auto auth_header = (struct auth_hdr *) (ipv6_header + *offset);
                ///< set the offset according to length of IPv6 Authentication Header
                *offset += (auth_header->ip6h_len + 2) << FOUR_OCTET_UNIT_TO_BYTES;
                ///< set the next header for following processing after the return from the this method
                *next_header = auth_header->ip6h_nxt;
            } else {    ///< invalid access to the memory, packet will be ignored
                *offset = 0;
            }
            break;
        }
        case NEXTHDR_IPV6: {        ///< Basic IPv6 Header
            ///< check correct access to the memory from that will be reading
            if (std::addressof(ipv6_header) + *offset + IPv6_HEADER_LEN <= this->end_addr) {
                ///< obtaining the Basic IPv6 Header
                auto ipv6_hdr = (struct ip6_hdr *) (ipv6_header + *offset);
                ///< set the offset according to length of Basic IPv6 Header
                *offset += IPv6_HEADER_LEN;
                ///< set the next header for following processing after the return from the this method
                *next_header = ipv6_hdr->ip6_nxt;
            } else {    ///< invalid access to the memory, packet will be ignored
                *offset = 0;
            }
            break;
        }
        case NEXTHDR_MOBILITY: {    ///< Mobility Header
            ///< check correct access to the memory from that will be reading
            if (std::addressof(ipv6_header) + *offset + sizeof(struct ipv6_mobility) <= this->end_addr) {
                ///< obtaining the IPv6 Mobility Header
                auto ipv6_mob = (struct ipv6_mobility *) (ipv6_header + *offset);
                ///< set the offset according to length of IPv6 Mobility Header
                *offset += (ipv6_mob->ip6m_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_mobility);
                ///< set the next header for following processing after the return from the this method
                *next_header = ipv6_mob->ip6m_nxt;
            } else {    ///< invalid access to the memory, packet will be ignored
                *offset = 0;
            }
            break;
        }
        default: {
            ///< unsupported type of IPv6 Extension Headers or another protocol (packet will be ignored in this case)
            *offset = 0;
            std::cerr << "Unsupported type of next header: " << next_header << " (packet will be ignored)" << std::endl;
        }
    }
}

unsigned char *
DnsExport::parse_transport_protocol(const unsigned char *packet, size_t offset, u_int8_t protocol, bool tcp_parse) {
    unsigned char *payload = nullptr;

    ///< check correct access to the memory from that will be reading
    if (protocol == IPPROTO_TCP and std::addressof(packet) + offset + sizeof(tcphdr) <= this->end_addr) {
        ///< obtaining the TCP Header
        const struct tcphdr *tcp_header = (tcphdr *) (packet + offset);
        ///< computing TCP Header Length
        size_t th_off = (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES);

        if (th_off < TCP_HEADER_MIN_LEN) { ///< check the valid length of TCP Header Length
            std::cerr << "Invalid TCP header length: " << th_off << "bytes" << std::endl;
        } else if ((this->network_payload_len - th_off) != 0) { ///< check the non-zero length of TCP Segment Length
            if (!tcp_parse) {   ///< only store TCP packets in first contact with it
                ///< allocation the memory for the store whole caught TCP Packet
                auto packet_copy = (unsigned char *) malloc(this->total_len);
                ///< copy TCP Packet to own memory, because authentic memory will be rewrite by next processing packet
                memcpy(packet_copy, packet, this->total_len);
                ///< create the trinity - packet, last allocated address cell, processing flag
                std::tuple<const unsigned char *, const unsigned char **, bool> packet_info = std::make_tuple(
                        packet_copy, this->end_addr, false);
                ///< store TCP packet to the vector
                this->tcp_packets.push_back(packet_info);
            } else if (std::addressof(packet) + offset + th_off <= this->end_addr) {
                ///< obtains DNS Payload from TCP Packets at second contact with it (after the possible reassembling)
                payload = (unsigned char *) (packet + offset + th_off);
            }
        }
    } else if (protocol == IPPROTO_UDP and std::addressof(packet) + offset + sizeof(struct udp_hdr) <= this->end_addr) {
        ///< obtains DNS Payload from UDP Packets
        payload = (unsigned char *) (packet + offset + sizeof(struct udp_hdr));
    }

    return payload;
}

unsigned char *DnsExport::parse_IPv4_packet(const unsigned char *packet, bool tcp_parse) {
    unsigned char *payload = nullptr;

    ///< check correct access to the memory from that will be reading
    if (std::addressof(packet) + this->datalink_header_length + sizeof(ip) <= this->end_addr) {
        ///< obtaining the IPv4 Header
        const struct ip *ip_header = (struct ip *) (packet + this->datalink_header_length);
        ///< check the minimal and maximal acceptable length of IPv4 Header in network layer
        if (ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES < IP_HEADER_MIN_LEN or
            ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES > IP_HEADER_MAX_LEN) {
            std::cerr << "Invalid IPv4 header length: " << ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES << " bytes"
                      << std::endl;
        } else {
            ///< set offset at the first byte after the IPv4 Header (begin of transport protocol)
            size_t hdr_offset = this->datalink_header_length + (ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES);
            ///< computing the length of the whole packet according to field IP->TOTAL_LENGTH
            this->total_len = ntohs(ip_header->ip_len) + this->datalink_header_length;
            ///< computing the length of data that are carried by IPv4 Header
            this->network_payload_len = this->total_len - hdr_offset;
            ///< calling the method to process header of transport protocol, so obtaining the payload of packet
            payload = this->parse_transport_protocol(packet, hdr_offset, ip_header->ip_p, tcp_parse);
        }
    }

    return payload;
}

unsigned char *DnsExport::parse_IPv6_packet(const unsigned char *packet, bool tcp_parse) {
    unsigned char *payload = nullptr;

    ///< check correct access to the memory from that will be reading
    if (std::addressof(packet) + this->datalink_header_length + IPv6_HEADER_LEN <= this->end_addr) {
        ///< obtaining the IPv6 Header
        const struct ip6_hdr *ipv6_header = (struct ip6_hdr *) (packet + this->datalink_header_length);

        ///< set the next header for following processing
        uint8_t next_header = ipv6_header->ip6_nxt;
        ///< set the offset according to length of Basic IPv6 Header
        unsigned ipv6_offset = IPv6_HEADER_LEN;

        ///< reprocessing to header of transport layer, in our case is valid only TCP and UDP Headers after the IPv6
        while (next_header != IPPROTO_TCP and next_header != IPPROTO_UDP) {
            ///< process the extension IPv6 Headers
            this->proccess_next_header(packet + this->datalink_header_length, &next_header, &ipv6_offset);
            ///< some error has occurred at processing of the extension header, packet will be ignored
            if (!ipv6_offset) {
                break;
            }
        }

        ///< check whether the loop ended at find the TCP or UDP header or with some error
        if (ipv6_offset) {
            ///< set offset at the first byte after the IPv6 Headers (begin of transport protocol)
            size_t hdr_offset = this->datalink_header_length + ipv6_offset;
            ///< computing the length of data that are carried by IPv6 Headers
            this->network_payload_len = ntohs(ipv6_header->ip6_plen);
            ///< computing the length of the whole packet according to field IP->PAYLOAD_LENGTH
            this->total_len = this->network_payload_len + hdr_offset;
            ///< check to valid transport protocols
            if (next_header == IPPROTO_TCP or next_header == IPPROTO_UDP) {
                ///< calling the method to process header of transport protocol, so obtaining the payload of packet
                payload = this->parse_transport_protocol(packet, hdr_offset, next_header, tcp_parse);
            }
        }
    }

    return payload;
}

unsigned char *DnsExport::my_pcap_handler(const unsigned char *packet, bool tcp_parse) {
    unsigned char *payload = nullptr;

    ///< check correct access to the memory from that will be reading
    if (std::addressof(packet) + this->datalink_header_length <= this->end_addr) {
        uint8_t network_protocol;
        ///< obtaining the byte that representing the type of protocol at the network layer
        memcpy(&network_protocol, (packet + this->datalink_header_length), sizeof(uint8_t));
        if ((network_protocol >> UPPER_BYTE_HALF) == NETWORK_IPv4) { ///< IPv4 Protocol
            payload = this->parse_IPv4_packet(packet, tcp_parse);
        } else if ((network_protocol >> UPPER_BYTE_HALF) == NETWORK_IPv6) { ///< IPv6 Protocol
            payload = this->parse_IPv6_packet(packet, tcp_parse);
        }
    }

    return payload;
}

char *DnsExport::transform_utc_time(const uint32_t utc_time) {
    auto raw_time = (time_t) utc_time;          ///< transform to time_t format
    struct tm *timeinfo = gmtime(&raw_time);    ///< transform to UTC time format

    auto *outstr = (char *) malloc(200);
    if (outstr == nullptr) {
        std::perror("malloc() failed: ");
        exit(EXIT_FAILURE);
    }

    ///< defined the format to write the time to the stats (according to RFC)
    const char *fmt = "%Y%m%d%H%M%S";
    if (strftime(outstr, 200, fmt, timeinfo) == 0) {
        std::cerr << "srtftime() failed";
    }
    return outstr;
}

std::string DnsExport::proccess_bits_array(unsigned char *record_payload) {
    std::stringstream result;

    ///< check correct access to the memory from that will be reading
    if (std::addressof(record_payload) + sizeof(uint16_t) <= (unsigned char **) this->end_addr) {
        ///< obtaining the field that contains the count of bytes in which are decoding the RR Types
        unsigned short nsec_bit_map_count;
        memcpy(&nsec_bit_map_count, record_payload, sizeof(nsec_bit_map_count));
        record_payload += sizeof(uint16_t);

        ///< check the correct shift according to the obtained value from DNS Answer (prevent before spoof value)
        if (std::addressof(record_payload) + ntohs(nsec_bit_map_count) <= (unsigned char **) this->end_addr) {
            std::vector<int> rr_indexes; ///< vector for RR Types that will be coded in bits_array
            for (unsigned i = 0; i < ntohs(nsec_bit_map_count); i++) {  ///< processing of the individual bytes of array
                ///< obtaining the individual bytes
                uint8_t byte_map;
                memcpy(&byte_map, record_payload, sizeof(byte_map));

                ///< magic with bytes
                byte_map = ((byte_map * 0x0802LU & 0x22110LU) | (byte_map * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16;
                for (unsigned j = 0; j < 8; j++) { ///< processing of the individual bits of byte
                    if ((byte_map >> j) & 1) {  ///< RR Type is present
                        ///< store the index of RR Type to the vector
                        rr_indexes.push_back(i * 8 + j);
                    }
                }
                ///< shift on the next byte in the whole array
                record_payload += sizeof(uint8_t);
            }
            ///< decoding of the individual RR Types that was decoded from the bits array
            for (const int &rr_index : rr_indexes) {
                result << " " << decode_rr_type(rr_index);
            }
        }
    }

    return (result.str().empty() ? "-" : result.str());
}


std::string DnsExport::decode_dns_record(int record_type, unsigned record_length, unsigned char *record_payload,
                                         unsigned char *buffer) {
    std::stringstream result;

    switch (record_type) {
        case DNS_ANS_TYPE_A: {
            ///< check the valid length of resource data and correct access to the memory from that will be reading
            if (record_length == 4 and
                std::addressof(record_payload) + sizeof(in_addr) <= (unsigned char **) this->end_addr) {
                in_addr addr;
                ///< obtaining the IPv4 address
                memcpy(&addr, record_payload, sizeof(in_addr));
                char addr_IPv4[INET_ADDRSTRLEN];
                ///< convert IPv4 address from binary to text form
                if (!inet_ntop(AF_INET, &addr, addr_IPv4, INET_ADDRSTRLEN)) {
                    std::perror("inet_ntop() failed:");
                } else {
                    result << "A \"" << addr_IPv4;
                }
            }
            break;
        }
        case DNS_ANS_TYPE_AAAA: {
            ///< check the valid length of resource data and correct access to the memory from that will be reading
            if (record_length == 16 and
                std::addressof(record_payload) + sizeof(in6_addr) <= (unsigned char **) this->end_addr) {
                in6_addr addr;
                ///< obtaining the IPv6 address
                memcpy(&addr, record_payload, sizeof(in6_addr));
                char addr_IPv6[INET6_ADDRSTRLEN];
                ///< convert IPv6 address from binary to text form
                if (!inet_ntop(AF_INET6, &addr, addr_IPv6, INET6_ADDRSTRLEN)) {
                    std::perror("inet_ntop failed():");
                } else {
                    result << "AAAA \"" << addr_IPv6;
                }
            }
            break;
        }
        case DNS_ANS_TYPE_MX: {
            unsigned index = 0;
            if (std::addressof(record_payload) + sizeof(unsigned short) <= (unsigned char **) this->end_addr) {
                unsigned short preference;
                ///< section of obtaining the preference field
                memcpy(&preference, record_payload, sizeof(preference));
                ///< section of obtaining the mail exchanger name
                std::string mx_name = this->read_name(record_payload + sizeof(unsigned short), buffer, &index);

                ///< check the valid length of resource data
                if (index + sizeof(unsigned short) == record_length and mx_name != "-") {
                    result << "MX \"" << ntohs(preference) << " " << mx_name;
                }
            }
            break;
        }
        case DNS_ANS_TYPE_SOA: {
            ///< section of obtaining field that contains primary name server
            unsigned offset = 0;
            std::string primary_name_server = this->read_name(record_payload, buffer, &offset);
            if (primary_name_server == "-") break;
            record_payload += offset;

            ///< section of obtaining the field that contains responsible authority email
            unsigned offset1 = 0;
            std::string responsible_auth_mail = this->read_name(record_payload, buffer, &offset1);
            if (responsible_auth_mail == "-") break;
            record_payload += offset1;

            ///< check the valid length of resource data and correct access to the memory from that will be reading
            if (std::addressof(record_payload) + sizeof(struct soa_record) <= (unsigned char **) this->end_addr and
                offset + offset1 + sizeof(soa_record) == record_length) {
                ///< section of obtaining the SOA record (for closer info about it check header file please)
                auto soa = (struct soa_record *) record_payload;

                ///< formatting of the result string that will represents the stats
                result << "SOA \"" << primary_name_server << " " << responsible_auth_mail << " " << htonl(soa->serial)
                       << " " << htonl(soa->refresh) << " " << htonl(soa->retry) << " " << htonl(soa->expire) << " "
                       << htonl(soa->min_ttl);
            }
            break;
        }
        case DNS_ANS_TYPE_RRSIG: {
            ///< check correct access to the memory from that will be reading
            if (std::addressof(record_payload) + sizeof(struct rrsig_record) <= (unsigned char **) this->end_addr) {
                ///< section of obtaining the RRSIG record (for closer info about it check header file please)
                auto rrsig = (struct rrsig_record *) record_payload;
                record_payload += sizeof(struct rrsig_record);

                ///< section of obtaining field that contains signers name
                unsigned offset = 0;
                std::string signers_name = this->read_name(record_payload, buffer, &offset);
                if (signers_name == "-") break;
                record_payload += offset;

                ///< computing the signature length according to summary RDLENGTH and length so far read
                unsigned signature_length = record_length - sizeof(struct rrsig_record) - offset;
                ///< check correct access to the memory from that will be reading
                if (std::addressof(record_payload) + signature_length <= (unsigned char **) this->end_addr) {
                    auto signature = new const unsigned char[signature_length]();
                    ///< section of obtaining field that contains signature value
                    memcpy((unsigned char *) signature, record_payload, signature_length);

                    ///< formatting of the result string that will represents the stats
                    result << "RRSIG \"" << decode_rr_type(ntohs(rrsig->type_covered)) << " "
                           << decode_algorithm(int(rrsig->algorithm)) << " " << unsigned(rrsig->labels) << " "
                           << ntohl(rrsig->orig_ttl) << " " << this->transform_utc_time(ntohl(rrsig->signature_exp))
                           << " " << this->transform_utc_time(ntohl(rrsig->signature_inc)) << " "
                           << ntohs(rrsig->key_tag) << " " << signers_name << " "
                           << this->base64_encode(signature, signature_length);
                }
            }
            break;
        }
        case DNS_ANS_TYPE_DS: {
            ///< check correct access to the memory from that will be reading
            if (std::addressof(record_payload) + sizeof(ds_record) <= (unsigned char **) this->end_addr) {
                ///< section of obtaining the DS record (for closer info about it check header file please)
                auto ds = (struct ds_record *) record_payload;
                record_payload += sizeof(ds_record);

                ///< computing the digest length according to summary RDLENGTH and size of DS Record
                unsigned digest_length = record_length - sizeof(ds_record);
                ///< check correct access to the memory from that will be reading
                if (std::addressof(record_payload) + digest_length <= (unsigned char **) this->end_addr) {
                    auto digest = new const unsigned char[digest_length]();
                    ///< section of obtaining field that contains digest value
                    memcpy((unsigned char *) digest, record_payload, digest_length);

                    ///< formatting of the result string that will represents the stats
                    result << "DS \"" << ntohs(ds->key_id) << " " << decode_algorithm(int(ds->algorithm)) << " "
                           << unsigned(ds->digest_type) << " ";
                    for (unsigned i = 0; i < digest_length; i++) {
                        result << std::hex << std::setfill('0') << std::setw(2)
                               << (unsigned short) ((digest[i] & 0xFF));
                    }
                }
            }
            break;
        }
        case DNS_ANS_TYPE_NSEC: {
            unsigned offset = 0;
            ///< obtaining the domain name
            std::string domain_name = this->read_name(record_payload, buffer, &offset);
            if (domain_name != "-") { ///< check whether the domain name exists
                record_payload += offset;
                ///< processing the bits array
                std::string bits_arr = this->proccess_bits_array(record_payload);
                if (bits_arr != "-") {
                    result << "NSEC \"" << domain_name << bits_arr;
                }
            }
            break;
        }
        case DNS_ANS_TYPE_DNSKEY: {
            ///< check correct access to the memory from that will be reading
            if (std::addressof(record_payload) + sizeof(struct dnskey_record) <= (unsigned char **) this->end_addr) {
                ///< section of obtaining the DNSKEY record (for closer info about it check header file please)
                auto dnskey = (struct dnskey_record *) record_payload;
                record_payload += sizeof(struct dnskey_record);

                ///< computing the public key length according to summary RDLENGTH and size of DNSKEY Record
                unsigned public_key_length = record_length - sizeof(struct dnskey_record);
                ///< check correct access to the memory from that will be reading
                if (std::addressof(record_payload) + public_key_length <= (unsigned char **) this->end_addr) {
                    auto public_key = new const unsigned char[public_key_length]();
                    ///< section of obtaining field that contains public_key value
                    memcpy((unsigned char *) public_key, record_payload, public_key_length);

                    ///< formatting the DNSKEY flags according to required format
                    std::stringstream dnskey_flags;
                    dnskey_flags << std::bitset<7>(dnskey->a1) << std::bitset<1>(dnskey->zone_key)
                                 << std::bitset<1>(dnskey->key_revoked) << std::bitset<6>(dnskey->a2)
                                 << std::bitset<1>(dnskey->key_signining) << std::endl;

                    ///< formatting of the result string that will represents the stats
                    result << "DNSKEY \"" << std::stoi(dnskey_flags.str(), nullptr, 2) << " "
                           << unsigned(dnskey->protocol) << " " << decode_algorithm(int(dnskey->algorithm)) << " "
                           << this->base64_encode(public_key, public_key_length);
                }
            }
            break;
        }
        case DNS_ANS_TYPE_NSEC3: {
            ///< check correct access to the memory from that will be reading
            if (std::addressof(record_payload) + sizeof(struct nsec3_record) <= (unsigned char **) this->end_addr) {
                ///< section of obtaining the NSEC3 record (for closer info about it check header file please)
                auto nsec3 = (struct nsec3_record *) record_payload;
                record_payload += sizeof(struct nsec3_record);

                ///< check correct access to the memory from that will be reading
                if (std::addressof(record_payload) + nsec3->salt_length + sizeof(uint8_t) <=
                    (unsigned char **) this->end_addr) {
                    auto salt = new const unsigned char[int(nsec3->salt_length)]();
                    ///< section of obtaining field that contains salt value
                    memcpy((unsigned char *) salt, record_payload, __size_t(nsec3->salt_length));
                    record_payload += int(nsec3->salt_length);

                    ///< section of obtaining field that contains the length of hash value
                    uint8_t hash_length;
                    memcpy(&hash_length, record_payload, sizeof(uint8_t));
                    record_payload += sizeof(uint8_t);

                    ///< check correct access to the memory from that will be reading
                    if (std::addressof(record_payload) + hash_length + sizeof(uint16_t) <=
                        (unsigned char **) this->end_addr) {
                        auto owner_name = new const unsigned char[int(hash_length)]();
                        ///< section of obtaining field that contains hash value
                        memcpy((unsigned char *) owner_name, record_payload, __size_t(hash_length));
                        record_payload += int(hash_length);

                        ///< section of processing the array contains the supported RR Types
                        std::string bits_arr = this->proccess_bits_array(record_payload);
                        if (bits_arr != "-") {
                            ///< formatting the hash value according to requirements, so to the base_32
                            int encode_length = Base32Encoder::GetEncode32Length(hash_length);
                            auto salt32 = new unsigned char[encode_length];

                            if (!Base32Encoder::Encode32(owner_name, hash_length, salt32)) {
                                std::cerr << "Internal error of program." << std::endl;
                            } else {
                                ///< formatting the NSEC3 flags according to required format
                                std::stringstream nsec3_flags;
                                nsec3_flags << std::bitset<7>(nsec3->reserved) << std::bitset<1>(nsec3->opt_out);

                                ///< formatting of the result string that will represents the stats
                                result << "NSEC3 \"" << unsigned(nsec3->algorithm) << " "
                                       << std::stoi(nsec3_flags.str(), nullptr, 2) << " "
                                       << ntohs(nsec3->iterations);

                                ///< formatting the salt value according to requirements, so to the hexadecimal format
                                if (nsec3->salt_length) {
                                    for (unsigned i = 0; i < nsec3->salt_length; i++) {
                                        result << std::hex << std::setfill('0') << std::setw(2)
                                               << (unsigned short) ((salt[i] & 0xFF));
                                    }
                                } else {
                                    result << " -";
                                }
                                ///< add the decoded supported RR Types from bits array
                                result << " " << salt32 << " " << bits_arr;
                            }
                        }
                    }
                }
            }
            break;
        }
        case DNS_ANS_TYPE_NSEC3PARAM: {
            ///< check correct access to the memory from that will be reading
            if (std::addressof(record_payload) + sizeof(struct nsec3_record) <= (unsigned char **) this->end_addr) {
                ///< section of obtaining the NSECPARAM record (for closer info about it check header file please)
                auto nsec3 = (struct nsec3_record *) record_payload;
                record_payload += sizeof(struct nsec3_record);

                ///< check correct access to the memory from that will be reading
                if (std::addressof(record_payload) + nsec3->salt_length <= (unsigned char **) this->end_addr) {
                    auto salt = new const unsigned char[int(nsec3->salt_length)]();
                    ///< section of obtaining field that contains salt value
                    memcpy((unsigned char *) salt, record_payload, __size_t(nsec3->salt_length));

                    ///< formatting the NSEC3PARAM flags according to required format
                    std::stringstream nsec3param_flags;
                    nsec3param_flags << std::bitset<7>(nsec3->reserved) << std::bitset<1>(nsec3->opt_out);

                    ///< formatting of the result string that will represents the stats
                    result << "NSEC3PARAM \"" << unsigned(nsec3->algorithm) << " "
                           << std::stoi(nsec3param_flags.str(), nullptr, 2) << " " << ntohs(nsec3->iterations) << " ";

                    ///< formatting the salt value according to requirements, so to the hexadecimal format
                    if (nsec3->salt_length) {
                        for (unsigned i = 0; i < nsec3->salt_length; i++) {
                            result << std::hex << std::setfill('0') << std::setw(2)
                                   << (unsigned short) ((salt[i] & 0xFF));
                        }
                    } else {
                        result << " -";
                    }
                }
            }
            break;
        }
        case DNS_ANS_TYPE_SRV: {
            ///< check correct access to the memory from that will be reading
            if (std::addressof(record_payload) + sizeof(struct srv_record) <= (unsigned char **) this->end_addr) {
                ///< section of obtaining the SRV record (for closer info about it check header file please)
                auto srv = (struct srv_record *) record_payload;
                record_payload += sizeof(struct srv_record);

                ///< section of obtaining the srv name field
                unsigned offset = 0;
                std::string srv_name = this->read_name(record_payload, buffer, &offset);
                if (srv_name != "-") {
                    ///< formatting of the result string that will represents the stats
                    result << "SRV \"" << ntohs(srv->priority) << " " << ntohs(srv->weight) << " " << ntohs(srv->port)
                           << " " << srv_name;
                }
            }
            break;
        }
        case DNS_ANS_TYPE_NS:
        case DNS_ANS_TYPE_CNAME:
        case DNS_ANS_TYPE_PTR: { ///< RR Types that contains only content in the text of the domain name
            unsigned offset = 0;
            std::string domain_name = this->read_name(record_payload, buffer, &offset);
            if (domain_name != "-")
                result << decode_rr_type(record_type) << " \"" << domain_name;
            break;
        }
        case DNS_ANS_TYPE_SPF:
        case DNS_ANS_TYPE_TXT: {    ///< RR Types that contains only content in the text form
            unsigned offset = 0;
            std::string txt_content = this->read_name(record_payload, buffer, &offset);
            if (txt_content != "-")
                result << decode_rr_type(record_type) << " \"" << (txt_content == "<ROOT>" ? "" : txt_content);
            break;
        }
        default: {      ///< unsupported RR Type
            result << decode_rr_type(record_type) << " \"";
            for (unsigned i = 0; i < record_length; i++) {
                result << std::hex << std::setfill('0') << std::setw(2)
                       << (unsigned short) ((record_payload[i] & 0xFF));
            }
            result << std::dec;
            break;
        }
    }   ///< end switch(RR_TYPE)

    result << "\"";

    return (result.str().empty() ? "-" : result.str());
}


void DnsExport::parse_payload(unsigned char *payload, bool tcp) {
    if (tcp) {
        payload += sizeof(unsigned short); ///< length field on the begin of the DNS Header in TCP Packets
    }

    ///< check correct access to the memory from that will be reading
    if (std::addressof(payload) + sizeof(struct DNS_HEADER) <= (unsigned char **) this->end_addr) {
        ///< section of obtaining the DNS Header (for closer info about it check header file please)
        const struct DNS_HEADER *dns_header = (struct DNS_HEADER *) payload;

        unsigned char *buffer = payload;
        std::string qname;
        unsigned end = 0;

        if (dns_header->QR == 0 and dns_header->QDCOUNT) {  ///< DNS QUERY
            ///< store DNS ID to the vector with IDs
            this->dns_ids.emplace_back(ntohs(dns_header->ID));
        } else if (dns_header->QR == 1 and dns_header->RCODE == 0x00 and
                   std::find(this->dns_ids.begin(), this->dns_ids.end(), ntohs(dns_header->ID)) !=
                   this->dns_ids.end()) {   ///< DNS RESPONSE
            ///< in the condition are controlling the individual flags that must be set (Response and Reply Code)
            ///< and control whether the DNS ID is present in the vector of IDs

            ///< find and delete the actually processing DNS ID from the vector of stored IDs
            auto it = std::find(this->dns_ids.begin(), this->dns_ids.end(), ntohs(dns_header->ID));
            if (it != this->dns_ids.end()) {
                this->dns_ids.erase(it);
            }

            payload += sizeof(struct DNS_HEADER);
            ///< skipping the DNS Queries array in the DNS Response
            for (unsigned i = 0; i < ntohs(dns_header->QDCOUNT); i++) {
                std::string tmp_ret_var = this->read_name(payload, buffer, &end);
                if (std::addressof(payload) + end + sizeof(struct QUESTION_FORMAT) <=
                    (unsigned char **) this->end_addr and tmp_ret_var != "-") {
                    payload += end + sizeof(struct QUESTION_FORMAT);
                } else {
                    return;
                }
            }

            ///< processing the DNS Answers array
            for (unsigned i = 0; i < ntohs(dns_header->ANCOUNT); i++) {
                ///< read the name field
                qname = this->read_name(payload, buffer, &end);
                ///< check correct access to the memory from that will be reading and right format of read name
                if (std::addressof(payload) + end + sizeof(struct RESOURCE_FORMAT) <=
                    (unsigned char **) this->end_addr and qname != "-") {
                    auto resource_format = (struct RESOURCE_FORMAT *) (payload + end);
                    payload += end + sizeof(struct RESOURCE_FORMAT);
                    ///< check whether the RDLENGTH is in range of allocated memory in given packet
                    if (std::addressof(payload) + ntohs(resource_format->RDLENGTH) <=
                        (unsigned char **) this->end_addr) {
                        ///< decoding the individual DNS Record from DNS Response
                        std::string result = this->decode_dns_record(ntohs(resource_format->TYPE),
                                                                     ntohs(resource_format->RDLENGTH), payload, buffer);
                        ///< some error has occurred at processing on DNS Record (the rest of packet will be ignored)
                        if (result == "-") {
                            return;
                        }

                        std::stringstream tmp;
                        tmp << qname << " ";
                        result.insert(0, tmp.str());

                        ///< add parsed DNS Record to the summary statistics
                        auto iter = stats.find(result);
                        if (iter != stats.end()) {
                            stats.find(result)->second++;
                        } else {
                            stats.insert(std::make_pair<std::string &, int>(result, 1));
                        }

                        ///< shift pointer on the next DNS Records
                        payload += ntohs(resource_format->RDLENGTH);
                    }
                } else {    ///< invalid access to the memory, packet will be ignored
                    return;
                }
            }   ///< end ANSWERS_COUNT loop
        }   ///< end DNS_RESPONSE condition
    }   ///< ///< invalid access to the memory, packet will be ignored
}   ///< end method

void DnsExport::proccess_tcp_packets() {
    ///< instantiation of TCP Reassembler commonly with length of datalink header
    TCPReassembler tcp_reassembler(this->datalink_header_length);
    ///< calling the method that executing the reassembling the TCP Packets stored in the vector
    std::vector<std::pair<const unsigned char *, const unsigned char **>> reassembled_tcp_packets =
            tcp_reassembler.reassembling_packets(&this->tcp_packets);
    ///< processing of reassembled packets
    for (std::pair<const unsigned char *, const unsigned char **> &tcp_packet : reassembled_tcp_packets) {
        ///< store the pointer to the end of caught packet
        this->end_addr = tcp_packet.second;
        ///< parsing the layers headers (link, network and transport)
        u_char *payload = this->my_pcap_handler(tcp_packet.first, true);
        if (payload) {
            ///< parse DNS Payload
            this->parse_payload(payload, true);
        }
    }
}


void DnsExport::run(int argc, char **argv) {
    ///< instantiation of Argument Parser
    ArgumentParser argument_parser;
    ///< processing of arguments
    argument_parser.parse_arguments(argc, argv);

    ///< check whether was given pcap file and is required its processing
    if (argument_parser.pcap_files.empty()) { ///< online sniffing on the given interface
        signal(SIGALRM, handle_alarm_signal);     ///< register the signal for ALARM
        alarm(time_in_seconds);             ///< set the alarm for sending the stats to syslog server
        ///< executing the sniffing
        this->execute_sniffing(argument_parser.interface_name.c_str(), true);
    } else {    ///< offline sniffing - processing of the given pcap file
        ///< gradually processing of given pcap files - one by one
        for (const std::string &file_name : argument_parser.pcap_files) {
            ///< executing the sniffing
            this->execute_sniffing(file_name.c_str());
        }
        ///< processing of caught TCP packets
        this->proccess_tcp_packets();
        ///< check whether the syslog server was given
        if (syslog_servers.empty()) {   ///< print stats on stdout
            for (std::pair<std::string, int> stats_item: stats) {
                std::cout << stats_item.first << " " << stats_item.second << std::endl;
            }
        } else {    ///< send stats to syslog server
            SyslogSender syslog_sender;
            syslog_sender.send_to_server(syslog_servers, stats);
        }
    }
}