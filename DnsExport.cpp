#include "DnsExport.h"
#include "TCPReassembler.h"
#include "SyslogSender.h"

unsigned int time_in_sec = 0;
std::vector<std::string> syslog_servers;
std::unordered_map<std::string, int> stats1;

/**
* Default Contructor.
*/
DnsExport::DnsExport() = default;


/**
* Destructor.
*/
DnsExport::~DnsExport() = default;

/*
 * TODO: auto check
 * TODO: relocate constant and structures, that are using in concretly modules
 * TODO: private methods
 * TODO: error states, return codes at all
 * TODO: ternary operator using
 */


void DnsExport::execute_sniffing(const char *name, bool mode) {
    char err_buff[PCAP_ERRBUF_SIZE];    /* Error string */
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct bpf_program fp;        /* The compiled filter expression */
    char filter_exp[] = "src port 53";    /* The filter expression */
    pcap_t *handle;

    /* Open the session in promiscuous mode */
    handle = mode ? pcap_open_live(name, BUFSIZ, 1, 1000, err_buff) : pcap_open_offline(name, err_buff);
    if (handle != nullptr) {
        // compile the filter
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) != -1) {
            // set the filter to the packet capture handle
            if (pcap_setfilter(handle, &fp) != -1) {
                this->datalink_header_length = get_length_of_datalink(pcap_datalink(handle));
                for (;;) {
                    while ((packet = pcap_next(handle, &header)) != nullptr) {
                        if (header.len > header.caplen) continue;

                        this->end_addr = std::addressof(packet) + header.caplen;
                        u_char *payload = this->my_pcap_handler(packet);
                        if (payload) {
                            this->parse_payload(payload, false);
                        }
                    }
                    if (!mode) break;
                }
            } else {
                std::perror("pcap_setfilter() failed:");
            }
        } else {
            std::perror("pcap_compile() failed:");
        }
    } else {
        std::perror(mode ? "pcap_open_live() failed:" : "pcap_open_offline() failed:");
    }
}


///< backward transformation domain name from the DNS form
std::string DnsExport::read_name(unsigned char *reader, unsigned char *buffer, unsigned *count) {
    std::string name;
    bool jumped = false;
    *count = 1;

    for (; *reader and std::addressof(reader) <= (unsigned char **) this->end_addr; reader++) {
        if (*reader >= 192) {
            if (std::addressof(reader) + sizeof(unsigned char) <= (unsigned char **) this->end_addr) {
                reader = buffer + (((*reader) << 8) + *(reader + 1) - 0xc000) - 1;
                jumped = true;
            } else {
                break;
            }
        } else {
            name.push_back(*reader);
        }

        if (!jumped) (*count)++;
    }

    if (jumped) (*count)++;

    for (unsigned i = 0; i < name.length(); i++) {
        auto label_length = (unsigned) name.at(i);
        name.insert(name.at(i) + i + 1, ".");
        name.erase(i, 1);
        i += label_length;
    }
    name.erase(name.length() - 1);

    return (*reader ? "" : name);
}


///< https://renenyffenegger.ch/notes/development/Base64/Encoding-and-decoding-base-64-with-cpp?fbclid=IwAR2R_B41ZHbJvIB5fpYIkwewW6idcMSEFnvKE_Pr72NqK1bl8Y-88kjv2qQ
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

    return ret;
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
            std::cerr << "Unknown type of next header: " << next_header << " (packet will be ignored)" << std::endl;
        }
    }
}

unsigned char *
DnsExport::parse_transport_protocol(const unsigned char *packet, size_t offset, u_int8_t protocol, bool tcp_parse) {
    unsigned char *payload = nullptr;

    if (protocol == IPPROTO_TCP and std::addressof(packet) + offset + sizeof(tcphdr) <= this->end_addr) {
        const struct tcphdr *tcp_header = (tcphdr *) (packet + offset);
        if ((tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES) < IP_HEADER_MIN_LEN) {
            std::cerr << "Invalid TCP header length: " << tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES << "bytes"
                      << std::endl;
        }

        if (!tcp_parse) {
            auto packet_copy = (unsigned char *) malloc(this->ip_total_len);
            memcpy(packet_copy, packet, this->ip_total_len);

            std::pair<const unsigned char *, const unsigned char **> packet_info = std::make_pair(packet_copy,
                                                                                                  this->end_addr);
            tcp_packets.push_back(packet_info);
        } else if (std::addressof(packet) + offset + (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES) <=
                   this->end_addr) {
            payload = (unsigned char *) (packet + offset + (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES));
        }
    } else if (protocol == IPPROTO_UDP and std::addressof(packet) + offset + sizeof(struct udphdr) <= this->end_addr) {
        payload = (unsigned char *) (packet + offset + sizeof(struct udphdr));
    }

    return payload;
}

unsigned char *DnsExport::parse_IPv4_packet(const unsigned char *packet, size_t offset, bool tcp_parse) {
    unsigned char *payload = nullptr;

    if (std::addressof(packet) + offset + sizeof(ip) <= this->end_addr) {
        const struct ip *ip_header = (struct ip *) (packet + offset);
        if (ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES < IP_HEADER_MIN_LEN or
            ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES > IP_HEADER_MAX_LEN) {
            std::cerr << "Invalid IPv4 header length: " << ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES << " bytes"
                      << std::endl;
        }
        this->ip_total_len = ntohs(ip_header->ip_len) + offset;
        payload = this->parse_transport_protocol(packet, offset + (ip_header->ip_hl << FOUR_OCTET_UNIT_TO_BYTES),
                                                 ip_header->ip_p, tcp_parse);
    }

    return payload;
}

unsigned char *DnsExport::parse_IPv6_packet(const unsigned char *packet, size_t offset, bool tcp_parse) {
    unsigned char *payload = nullptr;

    if (std::addressof(packet) + offset + IPv6_HEADER_LEN <= this->end_addr) {
        const struct ip6_hdr *ipv6_header = (struct ip6_hdr *) (packet + offset);

        uint8_t next_header = ipv6_header->ip6_nxt;
        unsigned ipv6_offset = IPv6_HEADER_LEN;

        while (next_header != IPPROTO_TCP and next_header != IPPROTO_UDP) {
            this->proccess_next_header(packet + offset, &next_header, &ipv6_offset);
            if (!ipv6_offset) {
                break;
            }
        }

        if (ipv6_offset) {
            this->ip_total_len = ntohs(ipv6_header->ip6_plen) + offset;
            if (next_header == IPPROTO_TCP or next_header == IPPROTO_UDP) {
                payload = this->parse_transport_protocol(packet, offset + ipv6_offset, next_header, tcp_parse);
            }
        }
    }

    return payload;
}

unsigned char *DnsExport::my_pcap_handler(const unsigned char *packet, bool tcp_parse) {
    unsigned char *payload = nullptr;

    if (std::addressof(packet) + this->datalink_header_length <= this->end_addr) {
        uint8_t network_protocol;
        memcpy(&network_protocol, (packet + this->datalink_header_length), sizeof(uint8_t));
        if ((network_protocol >> UPPER_BYTE_HALF) == NETWORK_IPv4) {
            payload = this->parse_IPv4_packet(packet, this->datalink_header_length, tcp_parse);
        } else if ((network_protocol >> UPPER_BYTE_HALF) == NETWORK_IPv6) {
            payload = this->parse_IPv6_packet(packet, this->datalink_header_length, tcp_parse);
        }
    }

    return payload;
}

char *DnsExport::transform_utc_time(const uint32_t utc_time) {
    auto raw_time = (time_t) utc_time;
    struct tm *timeinfo = gmtime(&raw_time);

    auto *outstr = (char *) malloc(200);
    const char *fmt = "%Y%m%d%H%M%S";
    if (strftime(outstr, 200, fmt, timeinfo) == 0) {
        std::cerr << "srtftime() failed";
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
            if (data_length == 4 and
                std::addressof(record_payload) + sizeof(in_addr) <= (unsigned char **) this->end_addr) {
                in_addr addr = {};
                memcpy(&addr, record_payload, sizeof(in_addr));
                char addr_IPv4[INET_ADDRSTRLEN];
                if (!inet_ntop(AF_INET, &addr, addr_IPv4, INET_ADDRSTRLEN)) {
                    std::perror("inet_ntop() failed:");
                } else {
                    result << "A " << addr_IPv4;
                }
            }
            break;
        }
        case DNS_ANS_TYPE_AAAA: {
            if (data_length == 16 and
                std::addressof(record_payload) + sizeof(in6_addr) <= (unsigned char **) this->end_addr) {
                in6_addr addr = {};
                memcpy(&addr, record_payload, sizeof(in6_addr));
                char addr_IPv6[INET6_ADDRSTRLEN];
                if (!inet_ntop(AF_INET6, &addr, addr_IPv6, INET6_ADDRSTRLEN)) {
                    std::perror("inet_ntop failed():");
                } else {
                    result << "AAAA " << addr_IPv6;
                }
            }
            break;
        }
        case DNS_ANS_TYPE_MX: {
            unsigned index = 0;
            if (std::addressof(record_payload) + sizeof(struct ns_preference) <= (unsigned char **) this->end_addr) {
                auto preference = (struct ns_preference *) record_payload;
                std::string mx_name = this->read_name(record_payload + sizeof(struct ns_preference), buffer, &index);

                if (index + sizeof(struct ns_preference) == data_length and !mx_name.empty()) {
                    result << "MX " << ntohs(preference->preference) << " " << mx_name;
                }
            }
            break;
        }
        case DNS_ANS_TYPE_SOA: {
            unsigned offset = 0;
            std::string primary_name_server = this->read_name(record_payload, buffer, &offset);
            if (primary_name_server.empty()) break;
            record_payload += offset;

            unsigned offset1 = 0;
            std::string responsible_auth_mail = this->read_name(record_payload, buffer, &offset1);
            if (responsible_auth_mail.empty()) break;
            record_payload += offset1;

            if (std::addressof(record_payload) + sizeof(struct soa_record) <= (unsigned char **) this->end_addr and
                offset + offset1 + sizeof(soa_record) == data_length) {
                auto soa = (struct soa_record *) record_payload;

                result << "SOA " << primary_name_server << " " << responsible_auth_mail << " " << htonl(soa->serial)
                       << " " << htonl(soa->refresh) << " " << htonl(soa->retry) << " " << htonl(soa->expire) << " "
                       << htonl(soa->min_ttl);
            }
            break;
        }
        case DNS_ANS_TYPE_RRSIG: {
            if (std::addressof(record_payload) + sizeof(struct rrsig_record) <= (unsigned char **) this->end_addr) {
                auto rrsig = (struct rrsig_record *) record_payload;
                record_payload += sizeof(struct rrsig_record);

                unsigned offset = 0;
                std::string signers_name = this->read_name(record_payload, buffer, &offset);
                if (signers_name.empty()) break;
                record_payload += offset;

                unsigned signature_length = data_length - sizeof(struct rrsig_record) - offset;
                if (std::addressof(record_payload) + signature_length <= (unsigned char **) this->end_addr) {
                    auto signature = new const unsigned char[signature_length]();
                    memcpy((unsigned char *) signature, record_payload, signature_length);
                    result << "RRSIG " << decode_rr_type(ntohs(rrsig->type_covered)) << " "
                           << decode_algorithm(int(rrsig->algorithm)) << " " << int(rrsig->labels) << " "
                           << ntohl(rrsig->orig_ttl) << " " << this->transform_utc_time(ntohl(rrsig->signature_exp))
                           << " " << this->transform_utc_time(ntohl(rrsig->signature_inc)) << " "
                           << ntohs(rrsig->key_tag) << " " << signers_name << " "
                           << this->base64_encode(signature, signature_length);
                }
            }
            break;
        }
        case DNS_ANS_TYPE_DS: {
            if (std::addressof(record_payload) + sizeof(ds_record) <= (unsigned char **) this->end_addr) {
                auto ds = (struct ds_record *) record_payload;
                record_payload += sizeof(ds_record);

                unsigned digest_length = data_length - sizeof(ds_record);
                if (std::addressof(record_payload) + digest_length <= (unsigned char **) this->end_addr) {
                    auto digest = new const unsigned char[digest_length]();
                    memcpy((unsigned char *) digest, record_payload, digest_length);

                    result << "DS ";
                    result << std::hex << ntohs(ds->key_id);
                    result << std::dec << " " << decode_algorithm(int(ds->algorithm)) << " " << int(ds->digest_type)
                           << " " << this->base64_encode(digest, digest_length);
                }
            }
            break;
        }
        case DNS_ANS_TYPE_NSEC: {
            unsigned offset = 0;
            std::string domain_name = this->read_name(record_payload, buffer, &offset);
            if (!domain_name.empty()) {
                record_payload += offset;
                std::string bits_arr = this->proccess_bits_array(record_payload);
                if (!bits_arr.empty()) {
                    result << "NSEC " << domain_name << bits_arr;
                }
            }
            break;
        }
        case DNS_ANS_TYPE_DNSKEY: {
            if (std::addressof(record_payload) + sizeof(struct dnskey_record) <= (unsigned char **) this->end_addr) {
                auto dnskey = (struct dnskey_record *) record_payload;
                record_payload += sizeof(struct dnskey_record);

                unsigned public_key_length = data_length - sizeof(struct dnskey_record);
                if (std::addressof(record_payload) + public_key_length <= (unsigned char **) this->end_addr) {
                    auto public_key = new const unsigned char[public_key_length]();
                    memcpy((unsigned char *) public_key, record_payload, public_key_length);

                    result << "DNSKEY " << (int) dnskey->zone_key << " " << (int) dnskey->key_revoked << " "
                           << (int) dnskey->key_signining << " " << (int) dnskey->a1 << (int) dnskey->a2 << " "
                           << (int) dnskey->protocol << " " << decode_algorithm(int(dnskey->algorithm)) << " "
                           << this->base64_encode(public_key, public_key_length);
                }
            }
            break;
        }
        case DNS_ANS_TYPE_NSEC3: {
            if (std::addressof(record_payload) + sizeof(struct nsec3_record) <= (unsigned char **) this->end_addr) {
                auto nsec3 = (struct nsec3_record *) record_payload;
                record_payload += sizeof(struct nsec3_record);

                if (std::addressof(record_payload) + nsec3->salt_length + sizeof(uint8_t) <=
                    (unsigned char **) this->end_addr) {
                    auto salt = new const unsigned char[int(nsec3->salt_length)]();
                    memcpy((unsigned char *) salt, record_payload, __size_t(nsec3->salt_length));
                    record_payload += int(nsec3->salt_length);

                    uint8_t hash_length;
                    memcpy(&hash_length, record_payload, sizeof(uint8_t));
                    record_payload += sizeof(uint8_t);

                    if (std::addressof(record_payload) + hash_length + sizeof(struct nsec_record) <=
                        (unsigned char **) this->end_addr) {
                        auto owner_name = new const unsigned char[int(hash_length)]();
                        memcpy((unsigned char *) owner_name, record_payload, __size_t(hash_length));
                        record_payload += int(hash_length);

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
                            if (!bits_arr.empty()) {
                                result << "NSEC3 " << decode_algorithm(int(nsec3->algorithm)) << " "
                                       << int(nsec3->opt_out) << " " << int(nsec3->reserved) << " "
                                       << ntohs(nsec3->iterations) << " " << int(nsec3->salt_length) << " "
                                       << this->base64_encode(salt, nsec3->salt_length) << " " << hash_length << " "
                                       << this->base64_encode(owner_name, hash_length) << bits_arr;
                            }
                        }
                    }
                }
            }
            break;
        }
        case DNS_ANS_TYPE_NSEC3PARAM: {
            if (std::addressof(record_payload) + sizeof(struct nsec3_record) <= (unsigned char **) this->end_addr) {
                auto nsec3 = (struct nsec3_record *) record_payload;
                record_payload += sizeof(struct nsec3_record);

                if (std::addressof(record_payload) + nsec3->salt_length <= (unsigned char **) this->end_addr) {
                    auto salt = new const unsigned char[int(nsec3->salt_length)]();
                    memcpy((unsigned char *) salt, record_payload, __size_t(nsec3->salt_length));
                    result << "NSEC3PARAM " << decode_algorithm(int(nsec3->algorithm)) << " " << int(nsec3->opt_out)
                           << " " << int(nsec3->reserved) << " " << ntohs(nsec3->iterations) << " "
                           << int(nsec3->salt_length) << " " << this->base64_encode(salt, nsec3->salt_length);
                }
            }
            break;
        }
        case DNS_ANS_TYPE_SRV: {
            if (std::addressof(record_payload) + sizeof(struct srv_record) <= (unsigned char **) this->end_addr) {
                auto srv = (struct srv_record *) record_payload;
                record_payload += sizeof(struct srv_record);
                unsigned offset = 0;
                std::string srv_name = this->read_name(record_payload, buffer, &offset);
                if (!srv_name.empty()) {
                    result << "SRV " << ntohs(srv->priority) << " " << ntohs(srv->weight) << " " << ntohs(srv->port)
                           << " " << srv_name;
                }
            }
            break;
        }
        case DNS_ANS_TYPE_NS:
        case DNS_ANS_TYPE_CNAME:
        case DNS_ANS_TYPE_PTR:
        case DNS_ANS_TYPE_SPF:
        case DNS_ANS_TYPE_TXT: {
            std::string txt_content = this->read_name(record_payload, buffer, record_length);
            if (!txt_content.empty()) result << decode_rr_type(record_type) << " " << txt_content;
            break;
        }
        default: {
            result << "UNSUPPORTED RECORD TYPE: " << decode_rr_type(record_type);
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
        std::string qname;
        unsigned end = 0;

        if (dns_header->QR == 1 and dns_header->RCODE == 0x00 and
            std::find(this->dns_ids.begin(), this->dns_ids.end(), ntohs(dns_header->ID)) == this->dns_ids.end()) {
            payload += sizeof(struct DNS_HEADER);
            for (unsigned i = 0; i < ntohs(dns_header->QDCOUNT); i++) {
                std::string tmp_ret_var = this->read_name(payload, buffer, &end);
                if (std::addressof(payload) + end + sizeof(struct QUESTION_FORMAT) <=
                    (unsigned char **) this->end_addr and !tmp_ret_var.empty()) {
                    payload += end + sizeof(struct QUESTION_FORMAT);
                } else {
                    return;
                }
            }

            for (unsigned i = 0; i < ntohs(dns_header->ANCOUNT); i++) {
                qname = this->read_name(payload, buffer, &end);
                if (std::addressof(payload) + end + sizeof(struct RESOURCE_FORMAT) <=
                    (unsigned char **) this->end_addr and !qname.empty()) {
                    auto resource_format = (struct RESOURCE_FORMAT *) (payload + end);
                    payload += end + sizeof(struct RESOURCE_FORMAT);
                    if (std::addressof(payload) + ntohs(resource_format->RDLENGTH) <=
                        (unsigned char **) this->end_addr) {
                        std::string result = this->decode_dns_record(ntohs(resource_format->TYPE),
                                                                     ntohs(resource_format->RDLENGTH),
                                                                     &end, payload,
                                                                     buffer);
                        if (result.empty()) {
                            return;
                        }

                        std::stringstream tmp;
                        tmp << qname << " ";
                        result.insert(0, tmp.str());

                        auto iter = this->stats.find(result);
                        if (iter != this->stats.end()) {
                            this->stats.find(result)->second++;
                            stats1.find(result)->second++;
                        } else {
                            this->stats.insert(std::make_pair<std::string &, int>(result, 1));
                            stats1.insert(std::make_pair<std::string &, int>(result, 1));
                        }

                        payload += ntohs(resource_format->RDLENGTH);
                    }
                } else {
                    return;
                }
            }
            this->dns_ids.emplace_back(ntohs(dns_header->ID));
        }
    }
}

void DnsExport::proccess_tcp_packets() {

    TCPReassembler tcp_reassembler(this->datalink_header_length);
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

void handle_signal(int _) {
    UNUSED(_);

    pid_t pid = fork();

    if (pid == 0) {
        SyslogSender syslog_sender;
        syslog_sender.sending_stats(syslog_servers, stats1);
        kill(getpid(), SIGTERM);
    } else if (pid > 0) {
        alarm(time_in_sec);
        return;
    } else {
        std::cerr << "System Error: fork() failed" << std::endl;
        exit(EXIT_FAILURE);
    }

}


void DnsExport::run(int argc, char **argv) {
    ArgumentParser argument_parser;
    argument_parser.parse_arguments(argc, argv);
    time_in_sec = argument_parser.time_in_seconds;
    syslog_servers = argument_parser.syslog_servers;

    if (argument_parser.pcap_files.empty()) {
        signal(SIGALRM, handle_signal);
        alarm(argument_parser.time_in_seconds);
        this->execute_sniffing(argument_parser.interface_name.c_str(), true);
    } else {
        for (const std::string &file_name : argument_parser.pcap_files) {
            this->execute_sniffing(file_name.c_str());
            this->proccess_tcp_packets();
            if (argument_parser.syslog_servers.empty()) {
                for (std::pair<std::string, int> stats_item: this->stats) {
                    std::cout << stats_item.first << " " << stats_item.second << std::endl;
                }
            } else {
                SyslogSender syslog_sender;
                syslog_sender.sending_stats(syslog_servers, stats1);
            }

        }
    }
}