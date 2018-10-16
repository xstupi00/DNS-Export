#include "DnsExport.h"
#include "ArgumentsParser.h"
#include "FileSniffer.h"
#include "InterfaceSniffer.h"
#include "TCPReassembler.h"

/**
* Default Contructor.
*/
DnsExport::DnsExport() = default;


/**
* Destructor.
*/
DnsExport::~DnsExport() = default;


void DnsExport::run(int argc, char **argv) {
    ArgumentParser argument_parser;
    argument_parser.parse_arguments(argc, argv);
    argument_parser.print_arguments();

    for (const std::string &file_name : argument_parser.pcap_files) {
        FileSniffer file_sniffer;
        file_sniffer.parse_pcap_file(file_name.c_str());
    }

    InterfaceSniffer interface_sniffer;
    interface_sniffer.sniffing_interface(argument_parser.interface_name, argument_parser.time_in_seconds);
}

///< backward transformation domain name from the DNS form
u_char *DnsExport::read_name(unsigned char *reader, unsigned char *buffer, int *count) {
    unsigned char *name;
    unsigned int p = 0, jumped = 0, offset;
    int i, j;

    *count = 1;
    name = (unsigned char *) malloc(256);
    name[0] = '\0';

    // read the names in 3www6google3com format
    while (*reader) {
        if (*reader >= 192) {
            offset = (*reader) * 256 + *(reader + 1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; // we have jumped to another location so counting wont go up!
        } else {
            name[p++] = *reader;
        }

        reader = reader + 1;

        if (!jumped)
            *count = *count + 1; // if we havent jumped to another location then we can count up
    }

    name[p] = '\0'; // string complete
    if (jumped == 1) {
        *count = *count + 1; // number of steps we actually moved forward in the packet
    }

    // now convert 3www6google3com0 to www.google.com
    for (i = 0; i < (int) strlen((const char *) name); i++) {
        p = name[i];
        for (j = 0; j < (int) p; j++) {
            name[i] = name[i + 1];
            i = i + 1;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0'; // remove the last dot

    return name;
}


void DnsExport::proccess_next_header(const unsigned char *ipv6_header, uint8_t *next_header, unsigned *offset) {
    switch (*next_header) {
        case NEXTHDR_FRAGMENT: {
            auto ipv6_frag = (struct ip6_frag *) (ipv6_header + *offset);
            *offset += sizeof(struct ip6_frag);
            *next_header = ipv6_frag->ip6f_nxt;
            break;
        }
        case NEXTHDR_DEST: {
            auto ipv6_dest = (struct ipv6_dest *) (ipv6_header + *offset);
            *offset += (ipv6_dest->ip6d_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_dest);
            *next_header = ipv6_dest->ip6d_nxt;
            break;
        }
        case NEXTHDR_HOP: {
            auto ipv6_hop_hdr = (struct ipv6_hbh *) (ipv6_header + *offset);
            *offset += (ipv6_hop_hdr->ip6h_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_hbh);
            *next_header = ipv6_hop_hdr->ip6h_nxt;
            break;
        }
        case NEXTHDR_ROUTING: {
            auto ipv6_rthdr = (struct ipv6_rthdr *) (ipv6_header + *offset);
            *offset += (ipv6_rthdr->ip6r_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_rthdr);
            *next_header = ipv6_rthdr->ip6r_nxt;
            break;
        }
        case NEXTHDR_AUTH: {
            auto auth_header = (struct auth_hdr *) (ipv6_header + *offset);
            *offset += (auth_header->ip6h_len + 2) << FOUR_OCTET_UNIT_TO_BYTES;
            *next_header = auth_header->ip6h_nxt;
            break;
        }
        case NEXTHDR_IPV6: {
            auto ipv6_hdr = (struct ip6_hdr *) (ipv6_header + *offset);
            *offset += IPv6_HEADER_LEN;
            *next_header = ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            break;
        }
        case NEXTHDR_MOBILITY: {
            auto ipv6_mob = (struct ipv6_mobility *) (ipv6_header + *offset);
            *offset += (ipv6_mob->ip6m_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_mobility);
            *next_header = ipv6_mob->ip6m_nxt;
            break;
        }
        case NEXTHDR_SCTP: {
            *offset = 0;
            std::cerr << "Protocol SCTP is don't supported (packet will be ignored)." << endl;
            break;
        }
        case NEXTHDR_ICMP: {
            *offset = 0;
            //std::cerr << "Protocol ICMP is don't supported (packet will be ignored)." << endl;
            break;
        }
        case NEXTHDR_NONE: {
            *offset = 0;
            std::cerr << "Missing application protocol (packer will be ignored)." << endl;
            break;
        }
        case NEXTHDR_ESP: {
            *offset = 0;
            std::cerr << "??? ESP ???" << endl;
            break;
        }
        case NEXTHDR_GRE: {
            *offset = 0;
            std::cerr << "??? GRE ???" << endl;
            break;
        }
        default: {
            *offset = 0;
            std::cerr << "Unknown type of next header: " << next_header << "(packet will be ignored)" << endl;
        }
    }
}

u_char *
DnsExport::parse_transport_protocol(const unsigned char *packet, unsigned offset, u_int8_t protocol, bool tcp_parse) {

    u_char *payload = nullptr;

    if (protocol == IPPROTO_TCP) {
        const struct tcphdr *tcp_header = (tcphdr *) (packet + sizeof(struct ether_header) + offset);
        if ((tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES) < IP_HEADER_MIN_LEN) {
            std::cerr << "Invalid TCP header length: " << tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES << "bytes"
                      << endl;
        }

        if (!tcp_parse) {
            const struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
            auto *packet_copy = (unsigned char *) malloc(ntohs(ip_header->ip_len) + sizeof(struct ether_header));
            memcpy(packet_copy, packet, ntohs(ip_header->ip_len) + sizeof(struct ether_header));
            tcp_packets.push_back(packet_copy);
        } else {
            payload = (u_char *) (packet + sizeof(struct ether_header) + offset +
                                  (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES));
        }
    } else if (protocol == IPPROTO_UDP) {
        payload = (u_char *) (packet + sizeof(struct ether_header) + offset + sizeof(struct udphdr));
    }

    return payload;
}

u_char *DnsExport::parse_IPv4_packet(const unsigned char *packet, bool tcp_parse) {
    const struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));

    if (ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES < IP_HEADER_MIN_LEN ||
        ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES > IP_HEADER_MAX_LEN) {
        std::cerr << "Invalid IP header length: " << ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES << "bytes" << endl;
    }

    u_char *payload = this->parse_transport_protocol(packet, ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES,
                                                     ip_header->ip_p, tcp_parse);

    return payload;
}

u_char *DnsExport::parse_IPv6_packet(const unsigned char *packet, bool tcp_parse) {
    const struct ip6_hdr *ipv6_header = (struct ip6_hdr *) (packet + sizeof(struct ether_header));

    uint8_t next_header = ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    unsigned offset = IPv6_HEADER_LEN;

    while (next_header != IPPROTO_TCP && next_header != IPPROTO_UDP) {
        this->proccess_next_header(packet + sizeof(struct ether_header), &next_header, &offset);
        if (!offset) {
            break;
        }
    }

    u_char *payload = this->parse_transport_protocol(packet, offset, next_header, tcp_parse);

    return payload;
}

u_char *DnsExport::my_pcap_handler(const unsigned char *packet, bool tcp_parse) {
    u_char *payload = nullptr;

    const struct ether_header *ethernet_header = (struct ether_header *) packet;

    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
        payload = this->parse_IPv4_packet(packet, tcp_parse);
    } else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IPV6) {
        payload = this->parse_IPv6_packet(packet, tcp_parse);
    }
    return payload;
}

char *DnsExport::transform_utc_time(const uint32_t utc_time) {
    auto raw_time = (time_t) utc_time;
    struct tm *timeinfo = localtime(&raw_time);

    auto *outstr = (char *) malloc(200);
    //const char* fmt = "%b %d, %G %X %Z";
    const char *fmt = "%Y%m%d%H%M%S";
    if (strftime(outstr, 200, fmt, timeinfo) == 0) {
        fprintf(stderr, "strftime returned 0");
        exit(EXIT_FAILURE);
    }
    return outstr;
}

std::stringstream DnsExport::proccess_bits_array(unsigned char *record_payload) {
    auto *nsec = (struct nsec_record *) record_payload;
    record_payload += sizeof(nsec_record);

    std::vector<int> rr_indexes;
    for (unsigned i = 0; i < ntohs(nsec->bit_maps_count); i++) {
        unsigned long byte_map;
        memcpy(&byte_map, record_payload, sizeof(byte_map));

        byte_map = ((byte_map * 0x0802LU & 0x22110LU) | (byte_map * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16;
        for (unsigned j = 0; j < 8; j++) {
            if ((byte_map >> j) & 1) {
                rr_indexes.push_back(i * 8 + j);
            }
        }
        record_payload += sizeof(byte_map);
    }

    std::stringstream result;
    for (const int &rr_index : rr_indexes) {
        result << decode_rr_type(rr_index) << " ";
    }

    return result;
}


std::string DnsExport::decode_dns_record(
        int record_type, int data_length, int *record_length, u_char *record_payload, u_char *buffer
) {
    std::stringstream result;
    switch (record_type) {
        case DNS_ANS_TYPE_A: {
            in_addr addr = {};
            memcpy(&addr, record_payload, sizeof(addr));
            char addr_IPv4[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, addr_IPv4, INET_ADDRSTRLEN);

            result << "A " << addr_IPv4;
            //std::cout << " Data (IPv4): " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_AAAA: {
            in6_addr addr = {};
            memcpy(&addr, record_payload, sizeof(addr));
            char addr_IPv6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr, addr_IPv6, INET6_ADDRSTRLEN);

            result << "AAAA " << addr_IPv6;
            //std::cout << " Data (IPv6): " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_MX: {
            auto preference = (struct ns_preference *) record_payload;
            auto *mx_name = (char *) this->read_name(record_payload + sizeof(uint16_t), buffer, record_length);

            result << "MX " << preference->preference << " " << mx_name;
            //std::cout <<" Data (MX) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_SOA: {
            int offset = 0;
            u_char *primary_name_server = this->read_name(record_payload, buffer, &offset);
            record_payload += offset;
            u_char *responsible_auth_mail = this->read_name(record_payload, buffer, &offset);
            record_payload += offset;
            auto soa = (struct soa_record *) record_payload;

            result << "SOA " << primary_name_server << " " << responsible_auth_mail << " " << htonl(soa->serial) << " "
                   << htonl(soa->refresh) << " " << htonl(soa->retry) << " " << htonl(soa->expire) << " "
                   << htonl(soa->min_ttl);
            //std::cout <<" Data (SOA) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_RRSIG: {
            auto rrsig = (struct rrsig_record *) record_payload;
            record_payload += sizeof(struct rrsig_record);
            int offset = 0;
            u_char *signers_name = this->read_name(record_payload, buffer, &offset);
            record_payload += offset;
            auto signature = new char[data_length - sizeof(struct rrsig_record) - offset];
            memcpy(signature, record_payload, data_length - sizeof(struct rrsig_record) - offset);

            result << "RRSIG " << ntohs(rrsig->type_covered) << " " << decode_algorithm(int(rrsig->algorithm)) << " "
                   << int(rrsig->labels) << " " << ntohl(rrsig->orig_ttl) << " "
                   << this->transform_utc_time(ntohl(rrsig->signature_exp)) << " "
                   << this->transform_utc_time(ntohl(rrsig->signature_inc)) << " " << ntohs(rrsig->key_tag) << " "
                   << signers_name << " (" << endl;

            for (unsigned i = 0; i < data_length - sizeof(struct rrsig_record) - offset; i++) {
                result << std::hex << (unsigned short) ((signature[i] & 0xFF));
            }
            result << std::dec << endl << ")";

            //std::cout << " Data (RRSIG) "<< result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_DS: {
            auto ds = (struct ds_record *) record_payload;
            record_payload += sizeof(ds_record);
            auto digest = new char[data_length - sizeof(struct ds_record)];
            memcpy(digest, record_payload, data_length - sizeof(struct ds_record));

            result << "DS " << ntohs(ds->key_id) << " " << decode_algorithm(int(ds->algorithm)) << " "
                   << int(ds->digest_type) << " (" << endl;

            for (unsigned i = 0; i < data_length - sizeof(struct ds_record); i++) {
                result << std::hex << (unsigned short) ((digest[i] & 0xFF));
            }
            result << std::dec << endl << ")";

            //std::cout << " Data (DS) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_NSEC: {
            int offset = 0;
            u_char *domain_name = this->read_name(record_payload, buffer, &offset);
            result << "NSEC " << domain_name << " ";
            record_payload += offset;

            result << this->proccess_bits_array(record_payload).str();

            //std::cout << " Data (NSEC) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_DNSKEY: {
            auto dnskey = (struct dnskey_record *) record_payload;
            record_payload += sizeof(ds_record);
            auto public_key = new char[data_length - sizeof(dnskey_record)];
            memcpy(public_key, record_payload, data_length - sizeof(dnskey_record));

            result << "DNSKEY " << (int) dnskey->zone_key << " " << (int) dnskey->key_revoked << " "
                   << (int) dnskey->key_signining << " " << (int) dnskey->a1 << (int) dnskey->a2 << " "
                   << (int) dnskey->protocol << " " << decode_algorithm(int(dnskey->algorithm)) << " (" << endl;

            for (unsigned i = 0; i < data_length - sizeof(dnskey_record); i++) {
                result << std::hex << (unsigned short) ((public_key[i] & 0xFF));
            }
            result << std::dec << endl << ")";

            //std::cout << " Data (DNSKEY) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_NSEC3: {
            auto nsec3 = (struct nsec3_record *) record_payload;
            record_payload += sizeof(struct nsec3_record);
            result << "NSEC3 " << decode_algorithm(int(nsec3->algorithm)) << " " << int(nsec3->opt_out) << " "
                   << int(nsec3->reserved) << " " << ntohs(nsec3->iterations) << " " << int(nsec3->salt_length)
                   << " ( ";

            auto salt = new char[int(nsec3->salt_length)];
            memcpy(salt, record_payload, __size_t(nsec3->salt_length));
            record_payload += int(nsec3->salt_length);
            for (unsigned i = 0; i < int(nsec3->salt_length); i++) {
                result << std::hex << (unsigned short) ((salt[i] & 0xFF));
            }

            uint8_t hash_length;
            memcpy(&hash_length, record_payload, sizeof(uint8_t));
            record_payload += sizeof(unsigned char);
            result << std::dec << " ) " << endl << int(hash_length) << " ( ";

            auto owner_name = new char[int(hash_length)];
            memcpy(owner_name, record_payload, __size_t(hash_length));
            record_payload += int(hash_length);
            for (unsigned i = 0; i < int(hash_length); i++) {
                result << std::hex << (unsigned short) ((owner_name[i] & 0xFF));
            }
            result << std::dec << " )" << endl;

            auto nsec = (struct nsec_record *) record_payload;
            record_payload += sizeof(nsec_record);

            std::vector<int> rr_indexes;
            for (unsigned i = 0; i < ntohs(nsec->bit_maps_count); i++) {
                unsigned long byte_map;
                memcpy(&byte_map, record_payload, sizeof(byte_map));

                byte_map = ((byte_map * 0x0802LU & 0x22110LU) | (byte_map * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16;
                for (unsigned j = 0; j < 8; j++) {
                    if ((byte_map >> j) & 1) {
                        rr_indexes.push_back(i * 8 + j);
                    }
                }
                record_payload += sizeof(byte_map);
            }
            result << std::dec << " )" << this->proccess_bits_array(record_payload).str() << endl;

            //std::cout << " Data (NSEC3) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_NSEC3PARAM: {
            auto nsec3 = (struct nsec3_record *) record_payload;
            record_payload += sizeof(struct nsec3_record);
            result << "NSEC3PARAM " << decode_algorithm(int(nsec3->algorithm)) << " " << int(nsec3->opt_out) << " "
                   << int(nsec3->reserved) << " " << ntohs(nsec3->iterations) << " " << int(nsec3->salt_length)
                   << " ( ";

            auto salt = new char[int(nsec3->salt_length)];
            memcpy(salt, record_payload, __size_t(nsec3->salt_length));
            for (unsigned i = 0; i < int(nsec3->salt_length); i++) {
                result << std::hex << (unsigned short) ((salt[i] & 0xFF));
            }
            result << std::dec << " ) ";

            //std::cout << " Data (NSEC3PARAM) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_SRV: {
            auto srv = (struct srv_record *) record_payload;
            record_payload += sizeof(struct srv_record);
            int offset = 0;
            result << "SRV " << ntohs(srv->priority) << " " << ntohs(srv->weight) << " " << ntohs(srv->port) << " "
                   << this->read_name(record_payload, buffer, &offset);

            //std::cout << " Data (SRV) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_NS: {
            result << "NS " << this->read_name(record_payload, buffer, record_length);
            break;
        }
        case DNS_ANS_TYPE_CNAME: {
            result << "CNAME " << this->read_name(record_payload, buffer, record_length);
            break;
        }
        case DNS_ANS_TYPE_PTR: {
            result << "PTR " << this->read_name(record_payload, buffer, record_length);
            break;
        }
        case DNS_ANS_TYPE_TXT: {
            result << "TXT " << this->read_name(record_payload, buffer, record_length);
            break;
        }
        default: {
            result << "UNKNOWN RECORD TYPE !!!" << record_type;
            break;
        }
    }
    return result.str();
}


void DnsExport::parse_payload(u_char *payload, bool tcp) {
    if (tcp) {
        payload += sizeof(unsigned short); // length field on the begin of the DNS Header
    }

    const struct DNS_HEADER *dns_header = (struct DNS_HEADER *) payload;

    u_char *buffer = payload;
    unsigned char *qname = {};

    int end = 0;
    if (dns_header->QR == 1 and ntohs(dns_header->RCODE) == 0 and ntohs(dns_header->ANCOUNT) > 0 and
        std::find(this->dns_ids.begin(), this->dns_ids.end(), ntohs(dns_header->ID)) == this->dns_ids.end()) {
        payload += sizeof(struct DNS_HEADER);
        for (unsigned i = 0; i < ntohs(dns_header->QDCOUNT); i++) {
            qname = this->read_name(payload, buffer, &end);
            payload += end + sizeof(struct QUESTION_FORMAT);
        }

        for (unsigned i = 0; i < ntohs(dns_header->ANCOUNT); i++) {
            this->read_name(payload, buffer, &end);
            payload += end;
            auto resource_format = (struct RESOURCE_FORMAT *) (payload);
            std::string result = this->decode_dns_record(ntohs(resource_format->TYPE), ntohs(resource_format->RDLENGTH),
                                                         &end, payload + sizeof(struct RESOURCE_FORMAT), buffer);

            std::stringstream tmp;
            tmp << qname << " ";
            result.insert(0, tmp.str());

            auto iter = this->stats.find(result);
            if (iter != this->stats.end()) {
                this->stats.find(result)->second++;
            } else {
                this->stats.insert(std::make_pair<std::string&, int>(result, 1));
            }

            payload += sizeof(struct RESOURCE_FORMAT) + ntohs(resource_format->RDLENGTH);
        }
        this->dns_ids.emplace_back(ntohs(dns_header->ID));
    }

}

void DnsExport::proccess_tcp_packets() {

    TCPReassembler tcp_reassembler;
    this->tcp_packets = tcp_reassembler.reassembling_packets(this->tcp_packets);
    for (const unsigned char *&tcp_packet : this->tcp_packets) {
        u_char *payload = this->my_pcap_handler(tcp_packet, true);
        if (payload) {
            this->parse_payload(payload, true);
        }
    }

    /*std::cout << "auth_hdr = " << sizeof(struct auth_hdr) << endl;
    std::cout << "ipv6_hbh = " << sizeof(struct ipv6_hbh) << endl;
    std::cout << "ipv6_dest = " << sizeof(struct ipv6_dest) << endl;
    std::cout << "ipv6_rthdr = " << sizeof(struct ipv6_rthdr) << endl;
    std::cout << "ipv6_mobility = " << sizeof(struct ipv6_mobility) << endl;
    std::cout << "ns_preference = " << sizeof(struct ns_preference) << endl;
    std::cout << "soa_record = " << sizeof(struct soa_record) << endl;
    std::cout << "rrsig_record = " << sizeof(struct rrsig_record) << endl;
    std::cout << "ds_record = " << sizeof(struct ds_record) << endl;
    std::cout << "srv_record = " << sizeof(struct srv_record) << endl;
    std::cout << "nsec_record = " << sizeof(struct nsec_record) << endl;
    std::cout << "nsec3_record = " << sizeof(struct nsec3_record) << endl;
    std::cout << "dnskey_record = " << sizeof(struct dnskey_record) << endl;
    std::cout << "dns_header = " << sizeof(struct DNS_HEADER) << endl;
    std::cout << "question_format = " << sizeof(struct QUESTION_FORMAT) << endl;
    std::cout << "resource_format = " << sizeof(struct RESOURCE_FORMAT) << endl;*/

}