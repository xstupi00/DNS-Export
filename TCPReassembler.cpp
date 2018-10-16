#include <iomanip>
#include "TCPReassembler.h"
#include "DataStructures.h"

using namespace std;

/**
* Default Contructor.
*/
TCPReassembler::TCPReassembler() = default;


/**
* Destructor.
*/
TCPReassembler::~TCPReassembler() = default;


u_char* TCPReassembler::parse_transport_protocol(const unsigned char* packet, unsigned offset, u_int8_t protocol, bool tcp_parse)
{
    u_char* payload = nullptr;
    int total = 0;

    const struct ether_header* ethernet_header = (struct ether_header*)packet;
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
        const struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
        total = ntohs(ip_header->ip_len);
    }
    else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IPV6) {
        const struct ip6_hdr* ipv6_header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
        total = ntohs(ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen);
    }

    if (protocol == IPPROTO_TCP) {
        const struct tcphdr *tcp_header = (tcphdr *) (packet + sizeof(struct ether_header) + offset);

        if (!tcp_parse) {
            this->tcp_sequence_number = ntohl(tcp_header->seq);
            this->tcp_segment_length = total - offset - (tcp_header->th_off<<FOUR_OCTET_UNIT_TO_BYTES);
            payload = (u_char *) (packet + sizeof(struct ether_header) + offset + (tcp_header->th_off<<FOUR_OCTET_UNIT_TO_BYTES));
            unsigned short* length = (unsigned short*) payload;
            payload += sizeof(unsigned short);
            this->dns_length = ntohs(*length);
            this->last_packet_length = total + sizeof(struct ether_header);
        } else {
            if (ntohl(tcp_header->seq) == this->tcp_sequence_number + tcp_segment_length) {
                this->tcp_sequence_number = ntohl(tcp_header->seq);
                this->tcp_segment_length = total - offset - (tcp_header->th_off<<FOUR_OCTET_UNIT_TO_BYTES);
                payload = (u_char *) (packet + sizeof(struct ether_header) + offset + (tcp_header->th_off<<FOUR_OCTET_UNIT_TO_BYTES));
            }
        }
        this->summary_length += tcp_segment_length;
    }

    return payload;
}

std::vector<const unsigned char*> TCPReassembler::reassembling_packets(std::vector<const unsigned char*> tcp_packets)
{

    std::vector<const unsigned char*> reassembled_tcp_packets;

    for (unsigned i = 0; i != tcp_packets.size(); i++) {
        const struct ether_header* ethernetHeader = (struct ether_header*)tcp_packets.at(i);

        if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
            this->parse_IPv4_packet(tcp_packets.at(i), false);
        }
        else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IPV6) {
            this->parse_IPv6_packet(tcp_packets.at(i), false);
        }

        const struct ip* ipHeader = (struct ip*)(tcp_packets.at(i) + sizeof(struct ether_header));
        const unsigned char *reassembled_packet = (const unsigned char*) malloc(ntohs(ipHeader->ip_len)+sizeof(struct ether_header));
        memcpy((unsigned char*)reassembled_packet, tcp_packets.at(i), ntohs(ipHeader->ip_len)+sizeof(struct ether_header));

        unsigned j = i+1; ///< in-order byte stream
        while (this->summary_length < this->dns_length && j < tcp_packets.size()) {
            const struct ether_header* ethernetHeader = (struct ether_header*)tcp_packets.at(j);
            u_char* payload = nullptr;

            if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
                payload = this->parse_IPv4_packet(tcp_packets.at(j), true);
            }
            else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IPV6) {
                payload = this->parse_IPv6_packet(tcp_packets.at(j), true);
            }

            if (payload) { ///< found the required ACK_NUMBER
                tcp_packets.erase(tcp_packets.begin()+j);
                reassembled_packet = (const unsigned char*) realloc((unsigned char*)reassembled_packet, (this->tcp_segment_length+this->last_packet_length));
                memcpy((unsigned char*)reassembled_packet+this->last_packet_length, payload, this->tcp_segment_length);
                this->last_packet_length += this->tcp_segment_length;
            } else {      ///< don't found the required ACK_NUMBER, will continue on the next packet
                j++;
            }
        }
        reassembled_tcp_packets.push_back(reassembled_packet);
        this->summary_length = 0;
    }

    return reassembled_tcp_packets;
}