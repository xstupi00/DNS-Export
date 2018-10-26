#include <sstream>
#include <iomanip>
#include "DnsExport.h"
#include "ArgumentsParser.h"
#include "TCPReassembler.h"
#include "SyslogSender.h"

/**
* Default Contructor.
*/
DnsExport::DnsExport() = default;


/**
* Destructor.
*/
DnsExport::~DnsExport() = default;

void DnsExport::parse_pcap_file(const char *pcap_file_name) {
    char errbuff[PCAP_ERRBUF_SIZE];    /* Error string */
    const unsigned char *packet;
    struct pcap_pkthdr header = {};
    struct bpf_program fp = {};        /* The compiled filter expression */
    char filter_exp[] = "src port 53";    /* The filter expression */

    /* Open the session in promiscuous mode */
    pcap_t *handle = pcap_open_offline(pcap_file_name, errbuff);
    if (handle == nullptr) {
        std::cerr << "Couldn't open file:" << endl;
    }

    // compile the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1)
        std::cerr << "pcap_compile() failed" << endl;

    // set the filter to the packet capture handle
    if (pcap_setfilter(handle, &fp) == -1)
        std::cerr << "pcap_setfilter() failed" << endl;

    while ((packet = pcap_next(handle, &header)) != nullptr) {
        if (header.len > header.caplen) continue;

        this->end_addr = std::addressof(packet) + header.caplen;
        u_char *payload = this->my_pcap_handler(packet, false);
        if (payload) {
            this->parse_payload(payload, false);
        }
    }
}

void DnsExport::sniffing_interface(std::string device_name, double time_in_seconds,
                                   std::vector<AddressWrapper> syslog_addr) {
    char errbuf[PCAP_ERRBUF_SIZE];    /* Error string */
    const unsigned char *packet;
    struct pcap_pkthdr header = {};
    struct bpf_program fp = {};        /* The compiled filter expression */
    char filter_exp[] = "src port 53";    /* The filter expression */


    /* Open the session in promiscuous mode */
    pcap_t *handle = pcap_open_live(device_name.c_str(), BUFSIZ, 1, 10000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device_name.c_str(), errbuf);
    }

    // compile the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "pcap_compile() failed" << endl;
    }

    // set the filter to the packet capture handle
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "pcap_setfilter() failed" << endl;
    }

    time_t start, end;
    double diff = 0;
    time(&start);
    for (;;) {
        while (((packet = pcap_next(handle, &header)) != nullptr)) {
            if (header.len > header.caplen) continue;

            u_char *payload = this->my_pcap_handler(packet, false);
            if (payload) {
                this->parse_payload(payload, false);
            }
        }
        diff = difftime(time(&end), start);
        if (std::isgreaterequal(diff, time_in_seconds)) {
            std::cout << "SEND TIME = " << diff << endl;
            SyslogSender syslog_sender;
            syslog_sender.sending_stats(syslog_addr, this->stats);
        }
    }
}


///< backward transformation domain name from the DNS form
unsigned char *DnsExport::read_name(unsigned char *reader, unsigned char *buffer, unsigned *count) {

    auto name = (unsigned char *) malloc(256); // TODO: rework to string
    name[0] = '\0';

    unsigned int p = 0, jumped = 0, offset;
    int i, j;
    *count = 1;

    // read the names in 3www6google3com format
    while (*reader && std::addressof(reader) <= (unsigned char **) this->end_addr) {
        if (*reader >= 192) {
            if (std::addressof(reader) + sizeof(unsigned char) <= (unsigned char **) this->end_addr) {
                offset = (*reader) * 256 + *(reader + 1) - 49152; //49152 = 11000000 00000000 ;)
                reader = buffer + offset - 1;
                jumped = 1; // we have jumped to another location so counting wont go up!
            } else {
                break;
            }
        } else {
            name[p++] = *reader;
        }
        reader++;

        if (!jumped) (*count)++; // if we havent jumped to another location then we can count up
    }

    name[p] = '\0'; // string complete
    if (jumped == 1) (*count)++; // number of steps we actually moved forward in the packet

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

    if (*reader) return nullptr;
    else return name;
}


void DnsExport::proccess_next_header(const unsigned char *ipv6_header, uint8_t *next_header, unsigned *offset) {
    switch (*next_header) {
        case NEXTHDR_FRAGMENT: {
            if (std::addressof(ipv6_header) + *offset + sizeof(struct ip6_frag) <= this->end_addr) {
                auto ipv6_frag = (struct ip6_frag *) (ipv6_header + *offset);
                *offset += sizeof(struct ip6_frag);
                *next_header = ipv6_frag->ip6f_nxt;
            } else {
                *offset = 0;
            }
            break;
        }
        case NEXTHDR_DEST: {
            if (std::addressof(ipv6_header) + *offset + sizeof(struct ipv6_dest) <= this->end_addr) {
                auto ipv6_dest = (struct ipv6_dest *) (ipv6_header + *offset);
                *offset += (ipv6_dest->ip6d_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_dest);
                *next_header = ipv6_dest->ip6d_nxt;
            } else {
                *offset = 0;
            }
            break;
        }
        case NEXTHDR_HOP: {
            if (std::addressof(ipv6_header) + *offset + sizeof(struct ipv6_hbh) <= this->end_addr) {
                auto ipv6_hop_hdr = (struct ipv6_hbh *) (ipv6_header + *offset);
                *offset += (ipv6_hop_hdr->ip6h_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_hbh);
                *next_header = ipv6_hop_hdr->ip6h_nxt;
            } else {
                *offset = 0;
            }
            break;
        }
        case NEXTHDR_ROUTING: {
            if (std::addressof(ipv6_header) + *offset + sizeof(struct ipv6_rthdr) <= this->end_addr) {
                auto ipv6_rthdr = (struct ipv6_rthdr *) (ipv6_header + *offset);
                *offset += (ipv6_rthdr->ip6r_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_rthdr);
                *next_header = ipv6_rthdr->ip6r_nxt;
            } else {
                *offset = 0;
            }
            break;
        }
        case NEXTHDR_AUTH: {
            if (std::addressof(ipv6_header) + *offset + sizeof(struct auth_hdr) <= this->end_addr) {
                auto auth_header = (struct auth_hdr *) (ipv6_header + *offset);
                *offset += (auth_header->ip6h_len + 2) << FOUR_OCTET_UNIT_TO_BYTES;
                *next_header = auth_header->ip6h_nxt;
            } else {
                *offset = 0;
            }
            break;
        }
        case NEXTHDR_IPV6: {
            if (std::addressof(ipv6_header) + *offset + IPv6_HEADER_LEN <= this->end_addr) {
                auto ipv6_hdr = (struct ip6_hdr *) (ipv6_header + *offset);
                *offset += IPv6_HEADER_LEN;
                *next_header = ipv6_hdr->ip6_nxt;
            } else {
                *offset = 0;
            }
            break;
        }
        case NEXTHDR_MOBILITY: {
            if (std::addressof(ipv6_header) + *offset + sizeof(struct ipv6_mobility) <= this->end_addr) {
                auto ipv6_mob = (struct ipv6_mobility *) (ipv6_header + *offset);
                *offset += (ipv6_mob->ip6m_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_mobility);
                *next_header = ipv6_mob->ip6m_nxt;
            } else {
                *offset = 0;
            }
            break;
        }
        default: {
            *offset = 0;
            std::cerr << "Unknown type of next header: " << next_header << " (packet will be ignored)" << endl;
        }
    }
}

unsigned char *
DnsExport::parse_transport_protocol(const unsigned char *packet, unsigned offset, u_int8_t protocol, bool tcp_parse) {
    unsigned char *payload = nullptr;

    if (protocol == IPPROTO_TCP and
        std::addressof(packet) + sizeof(struct ether_header) + offset + sizeof(tcphdr) <= this->end_addr) {
        const struct tcphdr *tcp_header = (tcphdr *) (packet + sizeof(struct ether_header) + offset);
        if ((tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES) < IP_HEADER_MIN_LEN) {
            std::cerr << "Invalid TCP header length: " << tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES
                      << "bytes"
                      << endl;
        }

        if (!tcp_parse) {
            const struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
            auto packet_copy = (unsigned char *) malloc(
                    ntohs(ip_header->ip_len) + sizeof(struct ether_header));
            memcpy(packet_copy, packet, ntohs(ip_header->ip_len) + sizeof(struct ether_header));

            std::pair<const unsigned char *, const unsigned char **> packet_info = std::make_pair(packet_copy,
                                                                                                  this->end_addr);
            tcp_packets.push_back(packet_info);
        } else if (&packet + sizeof(struct ether_header) + offset + (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES) <=
                   this->end_addr) {
            payload = (unsigned char *) (packet + sizeof(struct ether_header) + offset +
                                         (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES));
        }
    } else if (protocol == IPPROTO_UDP and
               std::addressof(packet) + sizeof(struct ether_header) + offset + sizeof(struct udphdr) <=
               this->end_addr) {
        payload = (unsigned char *) (packet + sizeof(struct ether_header) + offset + sizeof(struct udphdr));
    }

    return payload;
}

unsigned char *DnsExport::parse_IPv4_packet(const unsigned char *packet, bool tcp_parse) {
    unsigned char *payload = nullptr;

    if (std::addressof(packet) + sizeof(struct ether_header) + sizeof(ip) <= this->end_addr) {
        const struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
        if (ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES < IP_HEADER_MIN_LEN ||
            ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES > IP_HEADER_MAX_LEN) {
            std::cerr << "Invalid IP header length: " << ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES << "bytes"
                      << endl;
        }
        payload = this->parse_transport_protocol(packet, ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES,
                                                 ip_header->ip_p, tcp_parse);
    }

    return payload;
}

unsigned char *DnsExport::parse_IPv6_packet(const unsigned char *packet, bool tcp_parse) {
    unsigned char *payload = nullptr;

    if (std::addressof(packet) + sizeof(struct ether_header) + IPv6_HEADER_LEN <= this->end_addr) {
        const struct ip6_hdr *ipv6_header = (struct ip6_hdr *) (packet + sizeof(struct ether_header));

        uint8_t next_header = ipv6_header->ip6_nxt;
        unsigned offset = IPv6_HEADER_LEN;

        while (next_header != IPPROTO_TCP && next_header != IPPROTO_UDP) {
            this->proccess_next_header(packet + sizeof(struct ether_header), &next_header, &offset);
            if (!offset) {
                break;
            }
        }

        if (next_header == IPPROTO_TCP || next_header == IPPROTO_UDP) {
            payload = this->parse_transport_protocol(packet, offset, next_header, tcp_parse);
        }
    }

    return payload;
}

unsigned char *DnsExport::my_pcap_handler(const unsigned char *packet, bool tcp_parse) {
    unsigned char *payload = nullptr;

    if (std::addressof(packet) + sizeof(struct ether_header) <= this->end_addr) {
        const struct ether_header *ethernet_header = (struct ether_header *) packet;

        if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
            payload = this->parse_IPv4_packet(packet, tcp_parse);
        } else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IPV6) {
            payload = this->parse_IPv6_packet(packet, tcp_parse);
        }
    }
    return payload;
}

char *DnsExport::transform_utc_time(const uint32_t utc_time) {
    auto raw_time = (time_t) utc_time;
    struct tm *timeinfo = gmtime(&raw_time);

    auto *outstr = (char *) malloc(200);
    //const char* fmt = "%b %d, %G %X %Z";
    const char *fmt = "%Y%m%d%H%M%S";
    if (strftime(outstr, 200, fmt, timeinfo) == 0) {
        fprintf(stderr, "strftime returned 0");
        exit(EXIT_FAILURE);
    }
    return outstr;
}

std::string DnsExport::proccess_bits_array(unsigned char *record_payload) {
    std::stringstream result;

    if (std::addressof(record_payload) + sizeof(struct nsec_record) <= (unsigned char **) this->end_addr) {
        auto *nsec = (struct nsec_record *) record_payload;
        record_payload += sizeof(nsec_record);

        if (std::addressof(record_payload) + ntohs(nsec->bit_maps_count) <= (unsigned char **) this->end_addr) {
            std::vector<int> rr_indexes;
            for (unsigned i = 0; i < ntohs(nsec->bit_maps_count); i++) {
                uint8_t byte_map;
                memcpy(&byte_map, record_payload, sizeof(byte_map));

                byte_map = ((byte_map * 0x0802LU & 0x22110LU) | (byte_map * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16;
                for (unsigned j = 0; j < 8; j++) {
                    if ((byte_map >> j) & 1) {
                        rr_indexes.push_back(i * 8 + j);
                    }
                }
                record_payload += sizeof(uint8_t);
            }

            for (const int &rr_index : rr_indexes) {
                result << " " << decode_rr_type(rr_index);
            }
        }
    }

    return result.str();
}


std::string DnsExport::decode_dns_record(
        int record_type, unsigned data_length, unsigned *record_length, unsigned char *record_payload,
        unsigned char *buffer
) {
    std::stringstream result;

    switch (record_type) {
        case DNS_ANS_TYPE_A: {
            if (data_length == 4 &&
                std::addressof(record_payload) + sizeof(in_addr) <= (unsigned char **) this->end_addr) {
                in_addr addr = {};
                memcpy(&addr, record_payload, sizeof(in_addr));
                char addr_IPv4[INET_ADDRSTRLEN];
                if (!inet_ntop(AF_INET, &addr, addr_IPv4, INET_ADDRSTRLEN)) {
                    std::cerr << "inet_ntop() failed: " << std::strerror(errno) << endl;
                } else {
                    result << "A " << addr_IPv4;
                }
            }
            //std::cout << " Data (IPv4): " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_AAAA: {
            if (data_length == 16 &&
                std::addressof(record_payload) + sizeof(in6_addr) <= (unsigned char **) this->end_addr) {
                in6_addr addr = {};
                memcpy(&addr, record_payload, sizeof(in6_addr));
                char addr_IPv6[INET6_ADDRSTRLEN];
                if (!inet_ntop(AF_INET6, &addr, addr_IPv6, INET6_ADDRSTRLEN)) {
                    std::cerr << "inet_ntop() failed: " << std::strerror(errno) << endl;
                } else {
                    result << "AAAA " << addr_IPv6;
                }
            }
            //std::cout << " Data (IPv6): " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_MX: {
            unsigned index = 0;
            if (std::addressof(record_payload) + sizeof(struct ns_preference) <= (unsigned char **) this->end_addr) {
                auto preference = (struct ns_preference *) record_payload;
                auto mx_name = (char *) this->read_name(record_payload + sizeof(struct ns_preference), buffer, &index);

                if (index + sizeof(struct ns_preference) == data_length and mx_name) {
                    result << "MX " << ntohs(preference->preference) << " " << mx_name;
                }
            }
            //std::cout <<" Data (MX) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_SOA: {
            unsigned offset = 0;
            unsigned char *primary_name_server = this->read_name(record_payload, buffer, &offset);
            if (!primary_name_server) break;
            record_payload += offset;

            unsigned offset1 = 0;
            u_char *responsible_auth_mail = this->read_name(record_payload, buffer, &offset1);
            if (!responsible_auth_mail) break;
            record_payload += offset1;

            if (std::addressof(record_payload) + sizeof(struct soa_record) <= (unsigned char **) this->end_addr and
                offset + offset1 + sizeof(soa_record) == data_length) {
                auto soa = (struct soa_record *) record_payload;

                result << "SOA " << primary_name_server << " " << responsible_auth_mail << " " << htonl(soa->serial)
                       << " "
                       << htonl(soa->refresh) << " " << htonl(soa->retry) << " " << htonl(soa->expire) << " "
                       << htonl(soa->min_ttl);
            }
            //std::cout <<" Data (SOA) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_RRSIG: {
            if (std::addressof(record_payload) + sizeof(struct rrsig_record) <= (unsigned char **) this->end_addr) {
                auto rrsig = (struct rrsig_record *) record_payload;
                record_payload += sizeof(struct rrsig_record);

                unsigned offset = 0;
                u_char *signers_name = this->read_name(record_payload, buffer, &offset);
                if (!signers_name) break;
                record_payload += offset;

                unsigned signature_length = data_length - sizeof(struct rrsig_record) - offset;
                if (std::addressof(record_payload) + signature_length <= (unsigned char **) this->end_addr) {
                    auto signature = new char[signature_length];
                    memcpy(signature, record_payload, signature_length);

                    result << "RRSIG " << decode_rr_type(ntohs(rrsig->type_covered)) << " "
                           << decode_algorithm(int(rrsig->algorithm)) << " "
                           << int(rrsig->labels) << " " << ntohl(rrsig->orig_ttl) << " "
                           << this->transform_utc_time(ntohl(rrsig->signature_exp)) << " "
                           << this->transform_utc_time(ntohl(rrsig->signature_inc)) << " " << ntohs(rrsig->key_tag)
                           << " "
                           << signers_name << " ";

                    for (unsigned i = 0; i < signature_length; i++) {
                        //for (unsigned i = 0; i < 20; i++) {
                        result << std::hex << std::setfill('0') << setw(2) << (unsigned short) ((signature[i] & 0xFF));
                    }
                    //result << std::dec << "... ";
                }
            }

            //std::cout << " Data (RRSIG) "<< result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_DS: {
            if (std::addressof(record_payload) + sizeof(ds_record) <= (unsigned char **) this->end_addr) {
                auto ds = (struct ds_record *) record_payload;
                record_payload += sizeof(ds_record);

                unsigned digest_length = data_length - sizeof(ds_record);
                if (std::addressof(record_payload) + digest_length <= (unsigned char **) this->end_addr) {
                    auto digest = new char[digest_length];
                    memcpy(digest, record_payload, digest_length);

                    result << "DS ";
                    result << std::hex << ntohs(ds->key_id);
                    result << std::dec << " " << decode_algorithm(int(ds->algorithm)) << " " << int(ds->digest_type)
                           << " ";

                    for (unsigned i = 0; i < digest_length; i++) {
                        //for (unsigned i = 0; i < 20; i++) {
                        result << std::hex << std::setfill('0') << setw(2) << (unsigned short) ((digest[i] & 0xFF));
                    }
                    //result << std::dec << "... ";
                }
            }

            //std::cout << " Data (DS) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_NSEC: {
            unsigned offset = 0;
            u_char *domain_name = this->read_name(record_payload, buffer, &offset);
            if (domain_name) {
                result << "NSEC " << domain_name;
                record_payload += offset;
                std::string bits_arr = this->proccess_bits_array(record_payload);
                if (!bits_arr.empty()) result << bits_arr;
            }

            //std::cout << " Data (NSEC) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_DNSKEY: {
            if (std::addressof(record_payload) + sizeof(struct dnskey_record) <= (unsigned char **) this->end_addr) {
                auto dnskey = (struct dnskey_record *) record_payload;
                record_payload += sizeof(struct dnskey_record);

                unsigned public_key_length = data_length - sizeof(struct dnskey_record);
                if (std::addressof(record_payload) + public_key_length <= (unsigned char **) this->end_addr) {
                    auto public_key = new char[public_key_length];
                    memcpy(public_key, record_payload, public_key_length);

                    result << "DNSKEY " << (int) dnskey->zone_key << " " << (int) dnskey->key_revoked << " "
                           << (int) dnskey->key_signining << " " << (int) dnskey->a1 << (int) dnskey->a2 << " "
                           << (int) dnskey->protocol << " " << decode_algorithm(int(dnskey->algorithm)) << " ";

                    for (unsigned i = 0; i < public_key_length; i++) {
                        //for (unsigned i = 0; i < 20; i++) {
                        result << std::hex << std::setfill('0') << setw(2) << (unsigned short) ((public_key[i] & 0xFF));
                    }
                }
            }
            //result << std::dec << "... ";

            //std::cout << " Data (DNSKEY) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_NSEC3: {
            if (std::addressof(record_payload) + sizeof(struct nsec3_record) <= (unsigned char **) this->end_addr) {
                auto nsec3 = (struct nsec3_record *) record_payload;
                record_payload += sizeof(struct nsec3_record);
                result << "NSEC3 " << decode_algorithm(int(nsec3->algorithm)) << " " << int(nsec3->opt_out) << " "
                       << int(nsec3->reserved) << " " << ntohs(nsec3->iterations) << " " << int(nsec3->salt_length)
                       << " ";

                if (std::addressof(record_payload) + nsec3->salt_length + sizeof(uint8_t) <=
                    (unsigned char **) this->end_addr) {
                    auto salt = new char[int(nsec3->salt_length)];
                    memcpy(salt, record_payload, __size_t(nsec3->salt_length));
                    record_payload += int(nsec3->salt_length);

                    for (unsigned i = 0; i < int(nsec3->salt_length); i++) {
                        //for (unsigned i = 0; i < 20; i++) {
                        result << std::hex << std::setfill('0') << setw(2) << (unsigned short) ((salt[i] & 0xFF));
                    }

                    uint8_t hash_length;
                    memcpy(&hash_length, record_payload, sizeof(uint8_t));
                    record_payload += sizeof(uint8_t);
                    result << std::dec << "... " << endl << int(hash_length) << " ";

                    if (std::addressof(record_payload) + hash_length + sizeof(struct nsec_record) <=
                        (unsigned char **) this->end_addr) {
                        auto owner_name = new char[int(hash_length)];
                        memcpy(owner_name, record_payload, __size_t(hash_length));
                        record_payload += int(hash_length);

                        for (unsigned i = 0; i < int(hash_length); i++) {
                            //for (unsigned i = 0; i < 20; i++) {
                            result << std::hex << std::setfill('0') << setw(2)
                                   << (unsigned short) ((owner_name[i] & 0xFF));
                        }
                        //result << std::dec << "... " << endl;

                        auto nsec = (struct nsec_record *) record_payload;
                        record_payload += sizeof(nsec_record);

                        if (std::addressof(record_payload) + ntohs(nsec->bit_maps_count) <=
                            (unsigned char **) this->end_addr) {
                            std::vector<int> rr_indexes;
                            for (unsigned i = 0; i < ntohs(nsec->bit_maps_count); i++) {
                                uint8_t byte_map;
                                memcpy(&byte_map, record_payload, sizeof(byte_map));

                                byte_map = ((byte_map * 0x0802LU & 0x22110LU) | (byte_map * 0x8020LU & 0x88440LU)) *
                                           0x10101LU >> 16;
                                for (unsigned j = 0; j < 8; j++) {
                                    if ((byte_map >> j) & 1) {
                                        rr_indexes.push_back(i * 8 + j);
                                    }
                                }
                                record_payload += sizeof(uint8_t);
                            }
                            std::string bits_arr = this->proccess_bits_array(record_payload);
                            if (!bits_arr.empty()) result << std::dec << bits_arr;
                        }
                    }
                }
            }

            //std::cout << " Data (NSEC3) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_NSEC3PARAM: {
            if (std::addressof(record_payload) + sizeof(struct nsec3_record) <= (unsigned char **) this->end_addr) {
                auto nsec3 = (struct nsec3_record *) record_payload;
                record_payload += sizeof(struct nsec3_record);
                result << "NSEC3PARAM " << decode_algorithm(int(nsec3->algorithm)) << " " << int(nsec3->opt_out) << " "
                       << int(nsec3->reserved) << " " << ntohs(nsec3->iterations) << " " << int(nsec3->salt_length)
                       << " ";

                if (std::addressof(record_payload) + nsec3->salt_length <= (unsigned char **) this->end_addr) {
                    auto salt = new char[int(nsec3->salt_length)];
                    memcpy(salt, record_payload, __size_t(nsec3->salt_length));
                    for (unsigned i = 0; i < int(nsec3->salt_length); i++) {
                        //for (unsigned i = 0; i < 20; i++) {
                        result << std::hex << std::setfill('0') << setw(2) << (unsigned short) ((salt[i] & 0xFF));
                    }
                }
                //result << std::dec << "... ";
            }

            //std::cout << " Data (NSEC3PARAM) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_SRV: {
            if (std::addressof(record_payload) + sizeof(struct srv_record) <= (unsigned char **) this->end_addr) {
                auto srv = (struct srv_record *) record_payload;
                record_payload += sizeof(struct srv_record);
                unsigned offset = 0;
                unsigned char *srv_name = this->read_name(record_payload, buffer, &offset);
                if (srv_name) {
                    result << "SRV " << ntohs(srv->priority) << " " << ntohs(srv->weight) << " " << ntohs(srv->port)
                           << " " << srv_name;
                }
            }

            //std::cout << " Data (SRV) " << result.str() << endl;
            break;
        }
        case DNS_ANS_TYPE_NS: {
            unsigned char *name_server = this->read_name(record_payload, buffer, record_length);
            if (name_server) result << "NS " << name_server;
            break;
        }
        case DNS_ANS_TYPE_CNAME: {
            unsigned char *cname = this->read_name(record_payload, buffer, record_length);
            if (cname) result << "CNAME " << cname;
            break;
        }
        case DNS_ANS_TYPE_PTR: {
            unsigned char *domain_name = this->read_name(record_payload, buffer, record_length);
            if (domain_name) result << "PTR " << domain_name;
            break;
        }
        case DNS_ANS_TYPE_TXT: {
            unsigned char *txt_content = this->read_name(record_payload, buffer, record_length);
            if (txt_content) result << "TXT " << txt_content;
            break;
        }
        default: {
            result << "UNKNOWN RECORD TYPE: " << record_type;
            break;
        }
    }
    return result.str();
}


void DnsExport::parse_payload(unsigned char *payload, bool tcp) {
    if (tcp) {
        payload += sizeof(unsigned short); // length field on the begin of the DNS Header
    }

    if (std::addressof(payload) + sizeof(struct DNS_HEADER) <= (unsigned char **) this->end_addr) {
        const struct DNS_HEADER *dns_header = (struct DNS_HEADER *) payload;

        unsigned char *buffer = payload;
        unsigned char *qname = nullptr;
        unsigned end = 0;

        if (dns_header->QR == 1 and dns_header->RCODE == 0b0000) {// and
            //std::find(this->dns_ids.begin(), this->dns_ids.end(), ntohs(dns_header->ID)) == this->dns_ids.end()) {
            payload += sizeof(struct DNS_HEADER);
            for (unsigned i = 0; i < ntohs(dns_header->QDCOUNT); i++) {
                auto tmp_ret_var = this->read_name(payload, buffer, &end);
                if (std::addressof(payload) + end + sizeof(struct QUESTION_FORMAT) <=
                    (unsigned char **) this->end_addr and tmp_ret_var) {
                    payload += end + sizeof(struct QUESTION_FORMAT);
                } else {
                    return;
                }
            }

            for (unsigned i = 0; i < ntohs(dns_header->ANCOUNT); i++) {
                qname = this->read_name(payload, buffer, &end);
                if (std::addressof(payload) + end + sizeof(struct RESOURCE_FORMAT) <=
                    (unsigned char **) this->end_addr and qname) {
                    auto resource_format = (struct RESOURCE_FORMAT *) (payload + end);
                    payload += end + sizeof(struct RESOURCE_FORMAT);
                    if (std::addressof(payload) + ntohs(resource_format->RDLENGTH) <=
                        (unsigned char **) this->end_addr) {
                        std::string result = this->decode_dns_record(ntohs(resource_format->TYPE),
                                                                     ntohs(resource_format->RDLENGTH),
                                                                     &end, payload,
                                                                     buffer);
                        // error in the data_length
                        if (result.empty()) {
                            return;
                        }

                        std::stringstream tmp;
                        tmp << qname << " ";
                        result.insert(0, tmp.str());

                        auto iter = this->stats.find(result);
                        if (iter != this->stats.end()) {
                            this->stats.find(result)->second++;
                        } else {
                            this->stats.insert(std::make_pair<std::string &, int>(result, 1));
                        }

                        payload += ntohs(resource_format->RDLENGTH);
                    }
                } else {
                    return;
                }
            }
            //this->dns_ids.emplace_back(ntohs(dns_header->ID));
        }
    }
}

void DnsExport::proccess_tcp_packets() {

    TCPReassembler tcp_reassembler;
    this->tcp_packets = tcp_reassembler.reassembling_packets(this->tcp_packets);
    for (std::pair<const unsigned char *, const unsigned char **> &tcp_packet : this->tcp_packets) {
        this->end_addr = tcp_packet.second;
        u_char *payload = this->my_pcap_handler(tcp_packet.first, true);
        if (payload) {
            this->parse_payload(payload, true);
        }
    }
    this->tcp_packets.clear();
}

void DnsExport::run(int argc, char **argv) {
    ArgumentParser argument_parser;
    argument_parser.parse_arguments(argc, argv);
    //argument_parser.print_arguments();

    for (const std::string &file_name : argument_parser.pcap_files) {
        this->parse_pcap_file(file_name.c_str());
        this->proccess_tcp_packets();
        for (std::pair<std::string, int> stats_item: this->stats) {
            std::cout << stats_item.first << " " << stats_item.second << endl;
        }
        //SyslogSender syslog_sender;
        //syslog_sender.sending_stats(argument_parser.syslog_server_addr, this->stats);
    }

    if (!argument_parser.interface_name.empty()) {
        this->sniffing_interface(argument_parser.interface_name, argument_parser.time_in_seconds,
                                 argument_parser.syslog_server_addr);
    }
}
