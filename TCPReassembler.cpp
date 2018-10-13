#include <iomanip>
#include "TCPReassembler.h"
#include "DnsExport.h"

using namespace std;

/**
* Default Contructor.
*/
TCPReassembler::TCPReassembler() = default;


/**
* Destructor.
*/
TCPReassembler::~TCPReassembler() = default;


u_char* TCPReassembler::parse_tcp_protocol(const unsigned char* packet, unsigned offset, u_int8_t protocol, uint16_t total, bool compare)
{
    u_char* payload = nullptr;

    if (protocol == IPPROTO_TCP) {
        const struct tcphdr *tcpHeader = (tcphdr *) (packet + sizeof(struct ether_header) + offset);

        if (!compare) {
            this->tcp_sequence_number = ntohl(tcpHeader->seq);
            this->tcp_segment_length = total - offset - tcpHeader->th_off*4;
            payload = (u_char *) (packet + sizeof(struct ether_header) + offset + tcpHeader->th_off * 4);
            unsigned short* length = (unsigned short*) payload;
            payload += sizeof(unsigned short);
            this->dns_length = ntohs(*length);
            this->last_packet_length = total + sizeof(struct ether_header);
        } else {
            if (ntohl(tcpHeader->seq) == this->tcp_sequence_number + tcp_segment_length) {
                this->tcp_sequence_number = ntohl(tcpHeader->seq);
                this->tcp_segment_length = total - offset - tcpHeader->th_off*4;
                payload = (u_char *) (packet + sizeof(struct ether_header) + offset + tcpHeader->th_off * 4);
            }
        }
        this->summary_length += tcp_segment_length;
    }

    return payload;
}


u_char* TCPReassembler::parse_IPv4_tcp_packet(const unsigned char* packet, bool compare)
{
    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

    u_char* payload = this->parse_tcp_protocol(packet, ipHeader->ip_hl*4, ipHeader->ip_p, ntohs(ipHeader->ip_len), compare);

    return payload;
}

u_char* TCPReassembler::parse_IPv6_tcp_packet(const unsigned char *packet, bool compare)
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
    u_char* payload = this->parse_tcp_protocol(packet, offset, next_header, ntohs(ipv6pHeader->ip6_ctlun.ip6_un1.ip6_un1_plen), compare);

    return payload;
}

std::vector<const unsigned char*> TCPReassembler::reassembling_packets(std::vector<const unsigned char*> tcp_packets)
{
    std::vector<const unsigned char*> reassembled_tcp_packets;

    for (unsigned i = 0; i != tcp_packets.size(); i++) {
        const struct ether_header* ethernetHeader = (struct ether_header*)tcp_packets.at(i);

        if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
            this->parse_IPv4_tcp_packet(tcp_packets.at(i), false);
        }
        else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IPV6) {
            this->parse_IPv6_tcp_packet(tcp_packets.at(i), false);
        }

        const struct ip* ipHeader = (struct ip*)(tcp_packets.at(i) + sizeof(struct ether_header));
        const unsigned char *reassembled_packet = (const unsigned char*) malloc(ntohs(ipHeader->ip_len)+sizeof(struct ether_header));
        memcpy((unsigned char*)reassembled_packet, tcp_packets.at(i), ntohs(ipHeader->ip_len)+sizeof(struct ether_header));

        unsigned j = i+1; ///< in-order byte stream
        while (this->summary_length < this->dns_length && j < tcp_packets.size()) {
            const struct ether_header* ethernetHeader = (struct ether_header*)tcp_packets.at(j);
            u_char* payload = nullptr;

            if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
                payload = this->parse_IPv4_tcp_packet(tcp_packets.at(j), true);
            }
            else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IPV6) {
                payload = this->parse_IPv6_tcp_packet(tcp_packets.at(j), true);
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