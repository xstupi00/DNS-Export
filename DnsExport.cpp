#include "DnsExport.h"
#include "ArgumentsParser.h"
#include "FileSniffer.h"
#include "InterfaceSniffer.h"
#include "TCPReassembler.h"

#include <bitset>
#include <iomanip>
#include <netinet/ip6.h>

/**
* Default Contructor.
*/
DnsExport::DnsExport() = default;


/**
* Destructor.
*/
DnsExport::~DnsExport() = default;


void DnsExport::run(int argc, char **argv)
{
    ArgumentParser argument_parser;
    argument_parser.parse_arguments(argc, argv);
    argument_parser.print_arguments();

    for (unsigned i = 0; i < argument_parser.pcap_files.size(); i++) {
        FileSniffer fileSniffer;
        fileSniffer.parse_pcap_file(argument_parser.pcap_files.at(i).c_str());
    }

    //InterfaceSniffer interface_sniffer;
    //interface_sniffer.unknown_name_interface();
}

///< backward transformation domain name from the DNS form
u_char* DnsExport::read_name(unsigned char *reader, unsigned char *buffer, int *count)
{

    unsigned char *name;
    unsigned int p = 0, jumped = 0, offset;
    int i, j;

    *count = 1;
    name = (unsigned char *) malloc(256);

    name[0] = '\0';

    // read the names in 3www6google3com format
    while (*reader) {
        if (*reader >= 192) {
            offset = (*reader) * 256 + *(reader + 1) - 49152 + 2; //49152 = 11000000 00000000 ;)
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


uint8_t DnsExport::proccess_next_header(const unsigned char* ipv6_header, uint8_t* next_header, unsigned* offset) {
    switch(*next_header) {
        case NEXTHDR_FRAGMENT: {
            struct ip6_frag* ipv6_frag = (struct ip6_frag*) (ipv6_header + *offset);
            *offset += sizeof(struct ip6_frag);
            *next_header = ipv6_frag->ip6f_nxt;
            break;
        }
        case NEXTHDR_DEST: {
            struct ipv6_dest* ipv6_dest = (struct ipv6_dest*) (ipv6_header + *offset);
            *offset += (ipv6_dest->ip6d_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_dest);
            *next_header = ipv6_dest->ip6d_nxt;
            break;
        }
        case NEXTHDR_HOP: {
            struct ipv6_hbh* ipv6_hop_hdr = (struct ipv6_hbh*) (ipv6_header + *offset);
            *offset += (ipv6_hop_hdr->ip6h_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_hbh);
            *next_header = ipv6_hop_hdr->ip6h_nxt;
            break;
        }
        case NEXTHDR_ROUTING: {
            struct ipv6_rthdr* ipv6_rthdr = (struct ipv6_rthdr*) (ipv6_header + *offset);
            *offset += (ipv6_rthdr->ip6r_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_rthdr);
            *next_header = ipv6_rthdr->ip6r_nxt;
            break;
        }
        case NEXTHDR_AUTH: {
            struct auth_hdr* auth_header = (struct auth_hdr*) (ipv6_header + *offset);
            *offset += (auth_header->ip6h_len + 2) << FOUR_OCTET_UNIT_TO_BYTES;
            *next_header = auth_header->ip6h_nxt;
            break;
        }
        case NEXTHDR_IPV6:{
            struct ip6_hdr* ipv6_hdr = (struct ip6_hdr*) (ipv6_header + *offset);
            *offset += IPv6_HEADER_LEN;
            *next_header =  ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            break;
        }
        case NEXTHDR_MOBILITY:{
            struct ipv6_mobility* ipv6_mob = (struct ipv6_mobility*) (ipv6_header + *offset);
            *offset += (ipv6_mob->ip6m_len << EIGHT_OCTET_UNIT_TO_BYTES) + sizeof(struct ipv6_mobility);
            *next_header = ipv6_mob->ip6m_nxt;
            break;
        }
        case NEXTHDR_SCTP:{
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
        case NEXTHDR_ESP:{
            *offset = 0;
            std::cerr << "??? ESP ???" << endl;
            break;
        }
        case NEXTHDR_GRE:{
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

u_char* DnsExport::parse_transport_protocol(const unsigned char* packet, unsigned offset, u_int8_t protocol, bool tcp_parse) {

    u_char* payload = nullptr;

    if (protocol == IPPROTO_TCP) {
        const struct tcphdr *tcpHeader = (tcphdr *) (packet + sizeof(struct ether_header) + offset);
        if (tcpHeader->th_off * 4 < 20) {
            std::cerr << "Invalid TCP header length: " << tcpHeader->th_off * 4 << "bytes" << endl;
        }

        if (ntohs(tcpHeader->th_sport) == PORT_DNS_NUMBER) {
            if (!tcp_parse) {
                const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
                unsigned char *packet_copy = (unsigned char*) malloc(ntohs(ipHeader->ip_len)+sizeof(struct ether_header));
                memcpy(packet_copy, packet, ntohs(ipHeader->ip_len)+sizeof(struct ether_header));
                tcp_packets.push_back(packet_copy);
            } else {
                payload = (u_char *) (packet + sizeof(struct ether_header) + offset + tcpHeader->th_off * 4);
            }
        }
    } else if (protocol == IPPROTO_UDP) {
        const struct udphdr *udpHeader = (udphdr *) (packet + sizeof(struct ether_header) + offset);
        if (ntohs(udpHeader->source) == PORT_DNS_NUMBER) {
            payload = (u_char *) (packet + sizeof(struct ether_header) + offset + sizeof(struct udphdr));
        }
        //return(0); // stop udp
    }


    return payload;
}

u_char* DnsExport::parse_IPv4_packet(const unsigned char* packet, bool tcp_parse)
{
    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

    if (ipHeader->ip_hl*4 < IP_HEADER_MIN_LEN || ipHeader->ip_hl*4 > IP_HEADER_MAX_LEN) {
        std::cerr << "Invalid IP header length: " << ipHeader->ip_hl*4 << "bytes" << endl;
    }

    u_char* payload = this->parse_transport_protocol(packet, ipHeader->ip_hl*4, ipHeader->ip_p, tcp_parse);

    return payload;
}

u_char* DnsExport::parse_IPv6_packet(const unsigned char *packet, bool tcp_parse)
{
    const struct ip6_hdr* ipv6pHeader = (struct ip6_hdr*)(packet + sizeof(struct ether_header));

    uint8_t next_header = ipv6pHeader->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    unsigned offset = 40;

    while (next_header != IPPROTO_TCP && next_header != IPPROTO_UDP) {
        this->proccess_next_header(packet + sizeof(struct ether_header), &next_header, &offset);
        if (!offset) {
            break;
        }
    }

    u_char* payload = this->parse_transport_protocol(packet, offset, next_header, tcp_parse);

    return payload;
}

u_char* DnsExport::my_pcap_handler(const unsigned char* packet, bool tcp_parse)
{
    u_char* payload = nullptr;

    const struct ether_header* ethernetHeader = (struct ether_header*)packet;

    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        payload = this->parse_IPv4_packet(packet, tcp_parse);
    }
    else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IPV6) {
        payload = this->parse_IPv6_packet(packet, tcp_parse);
    }
    return payload;
}

char* DnsExport::transform_utc_time(const uint32_t utc_time)
{
    time_t raw_time = (time_t) utc_time;
    struct tm *timeinfo = localtime (&raw_time);

    auto* outstr = (char*) malloc(200);
    //const char* fmt = "%b %d, %G %X %Z";
    const char* fmt = "%Y%m%d%H%M%S";
    if (strftime(outstr, 200, fmt, timeinfo) == 0) {
        fprintf(stderr, "strftime returned 0");
        exit(EXIT_FAILURE);
    }
    return outstr;
}


void DnsExport::decode_dns_record(int record_type, int* record_length, u_char* record_payload, u_char* buffer) {
    record_payload -= sizeof(unsigned short);
    switch (record_type) {
        case DNS_ANS_TYPE_A: {
            in_addr addr;
            memcpy(&addr, record_payload, sizeof(addr));
            char addr_IPv4[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, addr_IPv4, INET_ADDRSTRLEN);
            std::cout << " Data (IPv4): " << inet_ntoa(addr) << endl;
            break;
        }
        case DNS_ANS_TYPE_AAAA: {
            in6_addr addr;
            memcpy(&addr, record_payload, sizeof(addr));
            char addr_IPv6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr, addr_IPv6, INET6_ADDRSTRLEN);
            std::cout << " Data (IPv6): " << addr_IPv6 << endl;
            break;
        }
        case DNS_ANS_TYPE_MX: {
            struct ns_preference* preference= (struct ns_preference*) record_payload;
            std::cout <<" Data (MX) " << ntohs(preference->preference) << " " <<\
             this->read_name(record_payload+ sizeof(uint16_t), buffer, record_length) << endl;
            break;
        }
        case DNS_ANS_TYPE_SOA: {
            int offset= 0;
            u_char * primary_name_server = this->read_name(record_payload, buffer, &offset);
            record_payload += offset;
            u_char* responsible_auth_mail = this->read_name(record_payload, buffer, &offset);
            record_payload += offset;
            struct soa_record* soa = (struct soa_record*) record_payload;
            std::cout <<" Data (SOA) " << primary_name_server << " " << responsible_auth_mail << " " <<\
            htonl(soa->serial) << " " << htonl(soa->refresh) << " " << htonl(soa->retry) << " " <<\
            htonl(soa->expire) << " " << htonl(soa->min_ttl) << endl;
            break;
        }
        case DNS_ANS_TYPE_RRSIG: {
            struct rrsig_record* rrsig = (struct rrsig_record*) record_payload;
            record_payload += sizeof(struct rrsig_record) - sizeof(unsigned short); // kkkk
            int offset = 0;
            u_char* signers_name = this->read_name(record_payload, buffer, &offset);
            record_payload += offset;
            char signature[128];
            memcpy(&signature, record_payload, sizeof(signature));

            for (unsigned i = 0; i < sizeof(signature); i++) {
                if(i % 8 == 0 && i != 0) std::cout << ' ';
                if(i % 16 == 0 && i != 0) std::cout << endl;
                std::cout << std::hex << setw(2) << (unsigned short)((signature[i] & 0xFF)) << " ";
            }
            std::cout << std::dec << endl;

            std::cout << " Data (RRSIG) "<< ntohs(rrsig->type_covered) << " " << int(rrsig->algorithm) << " " <<\
            int(rrsig->labels) << " " << ntohl(rrsig->orig_ttl) << " " <<\
            this->transform_utc_time(ntohl(rrsig->signature_exp)) <<\
            " " << this->transform_utc_time(ntohl(rrsig->signature_inc)) << " " <<\
            ntohs(rrsig->key_tag) << " " << signers_name << endl;
            break;
        }
        case DNS_ANS_TYPE_DS: {
            struct ds_record* ds = (struct ds_record*) record_payload;
            record_payload += sizeof(ds_record);
            char digest[32];
            memcpy(&digest, record_payload, sizeof(digest));
            for (unsigned i = 0; i < sizeof(digest); i++) {
                if(i % 8 == 0 && i != 0) std::cout << ' ';
                if(i % 16 == 0 && i != 0) std::cout << endl;
                std::cout << std::hex << setw(2) << (unsigned short)((digest[i] & 0xFF)) << " ";
            }
            std::cout << std::dec << endl;

            std::cout << " Data (DS) " << ntohs(ds->key_id) << " " << int(ds->algorithm) <<\
             " " << int(ds->digest_type) << endl;
            break;
        }
        case DNS_ANS_TYPE_NSEC: {
            int offset = 0;
            u_char *domain_name = this->read_name(record_payload, buffer, &offset);
            record_payload += offset;
            std::cout << " Data (NSEC) " << domain_name;
            struct nsec_record *nsec = (struct nsec_record *) record_payload;
            std::cout << " BYTES: " << ntohs(nsec->bit_maps_count) << " ";
            record_payload += sizeof(nsec_record);

            std::vector<int> rr_indexes;
            for (unsigned i = 0; i < ntohs(nsec->bit_maps_count); i++) {
                uint8_t byte_map;
                memcpy(&byte_map, record_payload, sizeof(byte_map));

                byte_map = ((byte_map * 0x0802LU & 0x22110LU) | (byte_map * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16;
                for (unsigned j = 0; j < 8; j++) {
                    if ((byte_map >> j) & 1) {
                        rr_indexes.push_back(i*8+j);
                    }
                }
                record_payload += sizeof(byte_map);
            }

            for (unsigned int i = 0; i < rr_indexes.size(); i++) {
                std::cout << decode_rr_type(rr_indexes.at(i)) <<" ";
            }
            std::cout << endl;
            break;
        }
        case DNS_ANS_TYPE_DNSKEY: {
            struct dnskey_record* dnskey = (struct dnskey_record*) record_payload;
            std::cout << "--------------------------------------------" << endl;
            std::cout << " Data (DNSKEY) ";
            break;
        }
        default: {
            std::cout << " Data (" << record_type << ") " << this->read_name(record_payload, buffer, record_length) << endl;
            break;
        }
    }
}

void DnsExport::parse_payload(u_char* payload) {
    const struct DNS_HEADER *dns_header = (struct DNS_HEADER *) payload;
    u_char* buffer = payload;

    int end = 0;
    if (dns_header->QR == 1 && ntohs(dns_header->RCODE) == 0 && ntohs(dns_header->ANCOUNT) > 0) {
        payload += sizeof(struct DNS_HEADER);
        for (unsigned i  = 0; i < ntohs(dns_header->QDCOUNT); i++) {
            std::cout << "Correct Answer ";
            unsigned char *qname = this->read_name(payload, buffer, &end);
            std::cout << "NAME: " << qname;
            payload += end;
            struct QUESTION_FORMAT *question_format = (struct QUESTION_FORMAT *) (payload);
            std::cout << " TYPE=" << ntohs(question_format->QTYPE) << " CLASS=" << ntohs(question_format->QCLASS)
                      << endl;
            payload += sizeof(struct QUESTION_FORMAT);
        }

        for (unsigned i = 0; i < ntohs(dns_header->ANCOUNT); i++) {
            std::cout << "NAME=" << this->read_name(payload, buffer, &end);
            payload += end;
            struct RESOURCE_FORMAT *resource_format = (struct RESOURCE_FORMAT *) (payload);
            std::cout << " TYPE=" << ntohs(resource_format->TYPE) << " CLASS=" << ntohs(resource_format->CLASS) << \
                 " TTL=" << ntohl(resource_format->TTL) << " RDLENGTH=" << ntohs(resource_format->RDLENGTH) << endl;

            this->decode_dns_record(ntohs(resource_format->TYPE), &end, payload+sizeof(struct RESOURCE_FORMAT), buffer);
            payload += sizeof(struct RESOURCE_FORMAT) + ntohs(resource_format->RDLENGTH) - sizeof(unsigned short);
        }
    }
}

void DnsExport::proccess_tcp_packets() {

    //for (unsigned i = 0; i < this->tcp_packets.size(); i++) {
    TCPReassembler tcp_reassembler;
    this->tcp_packets = tcp_reassembler.reassembling_packets(this->tcp_packets);
    /*for (unsigned i = 4; i < 5; i++) {
        //for (unsigned i = 0; i < sizeof(tcp); i++) {
        //    if(i % 8 == 0 && i != 0) std::cout << ' ';
        //    if(i % 16 == 0 && i != 0) std::cout << endl;

        const struct ether_header* ethernetHeader = (struct ether_header*)this->tcp_packets[i];

        if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
            std::cout << "ETHERNET" << endl;
        }

        //std::cout << "ETHETNER = " << ntohs(ethernetHeader->ether_type) << endl;

        const struct ip* ipHeader = (struct ip*)(this->tcp_packets[i] + sizeof(struct ether_header));

        if (ipHeader->ip_hl*4 < IP_HEADER_MIN_LEN || ipHeader->ip_hl*4 > IP_HEADER_MAX_LEN) {
            std::cerr << "Invalid IP header length: " << ipHeader->ip_hl*4 << "bytes" << endl;
        }

        if (ipHeader->ip_p == IPPROTO_TCP) {
            const struct tcphdr *tcpHeader = (tcphdr *) (this->tcp_packets[i] + sizeof(struct ether_header) + ipHeader->ip_hl*4);
            if (tcpHeader->th_off * 4 < 20) {
                std::cerr << "Invalid TCP header length: " << tcpHeader->th_off * 4 << "bytes" << endl;
            }

            std::cout << "PORT = " << ntohs(tcpHeader->th_sport) << endl;

            if (ntohs(tcpHeader->th_sport) == PORT_DNS_NUMBER) {
                std::cout << "DNS" << endl;
            }
        }


        std::cout << std::hex << setw(2) << (unsigned short)(this->tcp_packets[i][2964] & 0xFF) << endl;
        //std::cout << std::dec << endl;
    }*/

    for (unsigned i = 0; i < this->tcp_packets.size(); i++) {
        u_char *payload = this->my_pcap_handler(this->tcp_packets[i], true);
            if (payload) {
                this->parse_payload(payload);
            }
    }

    /*unsigned cnt = 0;
    std::cout << std::hex << cnt;
    cnt = cnt+2;
    unsigned j = 0;
    for (unsigned i = 66; i < 3297; i++) {
        if(j % 8 == 0 && j != 0) std::cout << ' ';
        if(j % 16 == 0 && j != 0){ std::cout << endl;
        std::cout << std::hex << cnt << "   ";}
        std::cout << std::hex << setw(2) << (unsigned short)((tcp_packets.at(4)[i] & 0xFF)) << " ";
        cnt+=1; j++;
    }
    std::cout << std::dec << endl;*/
}