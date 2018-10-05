#include "DnsExport.h"
#include "ArgumentsParser.h"
#include "FileSniffer.h"
#include "InterfaceSniffer.h"


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


u_char* DnsExport::my_pcap_handler(const unsigned char* packet)
{
    u_char* payload = nullptr;

    const struct ether_header* ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

        if (ipHeader->ip_p == IPPROTO_TCP) {
            //const struct tcphdr* tcpHeader = (tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
            payload = (u_char *) (packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            //const struct udphdr* udpHeader = (udphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
            payload = (u_char *) (packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
        }
    }
    return payload;
}


void DnsExport::decode_dns_record(int record_type, int* record_length, u_char* record_payload, u_char* buffer) {
    record_payload -= sizeof(unsigned short);
    switch (record_type) {
        case DNS_ANS_TYPE_A: {
            in_addr addr;
            addr.s_addr = *((uint32_t *)(record_payload));
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
            std::cout <<" Data (MX): " << this->read_name(record_payload, buffer, record_length) << endl;
            break;
        }
        case DNS_ANS_TYPE_CNAME: {
            std::cout <<" Data (CNAME): " << this->read_name(record_payload, buffer, record_length) << endl;
            break;
        }
        default: {
            std::cout <<  "Unknown record type." << endl;
            break;
        }
    }
}

void DnsExport::parse_payload(u_char* payload) {
    const struct DNS_HEADER *dns_header = (struct DNS_HEADER *) payload;
    u_char* buffer = payload;

    int end = 0;
    if (dns_header->QR == 1 && ntohs(dns_header->RCODE) == 0 && ntohs(dns_header->ANCOUNT) > 0) {
        std::cout << "Correct Answer ";
        payload = payload + sizeof(struct DNS_HEADER);
        unsigned char *qname = this->read_name(payload, buffer, &end);
        std::cout << "NAME: " << qname;
        payload += end;
        struct QUESTION_FORMAT *question_format = (struct QUESTION_FORMAT *) (payload);
        std::cout << " TYPE=" << ntohs(question_format->QTYPE) << " CLASS=" << ntohs(question_format->QCLASS) << endl;

        payload += sizeof(struct QUESTION_FORMAT);// + sizeof(unsigned short);

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