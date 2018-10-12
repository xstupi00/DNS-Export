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
            this->tcp_segment_length = total - offset - tcpHeader->th_off*4; // +2 == dns_length
            payload = (u_char *) (packet + sizeof(struct ether_header) + offset + tcpHeader->th_off * 4);
            const struct DNS_HEADER *dns_header = (struct DNS_HEADER *) payload;
            this->dns_length = ntohs(dns_header->length);
            this->last_packet_length = total + sizeof(struct ether_header);

            //std::cout << "DNS SEGMENT LENGTH = " << this->dns_length << endl;
            //std::cout << "TCP SEGMENT LENGTH = " << this->tcp_segment_length << endl;
        } else {
            //std::cout << ntohl(tcpHeader->seq) << " == " << this->tcp_sequence_number + tcp_segment_length << endl;
            if (ntohl(tcpHeader->seq) == this->tcp_sequence_number + tcp_segment_length) {
                //std::cout << "MATCH" << endl;
                this->tcp_sequence_number = ntohl(tcpHeader->seq);
                this->tcp_segment_length = total - offset - tcpHeader->th_off*4;
                payload = (u_char *) (packet + sizeof(struct ether_header) + offset + tcpHeader->th_off * 4);

                //std::cout << "TCP SEGMENT LENGTH = " << this->tcp_segment_length << endl;
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
        //std::cout << "BEGIN RUN PACKET: " << i << " " << tcp_packets.size() << endl;
        const struct ether_header* ethernetHeader = (struct ether_header*)tcp_packets.at(i);

        if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
            this->parse_IPv4_tcp_packet(tcp_packets.at(i), false);
        }
        else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IPV6) {
            this->parse_IPv6_tcp_packet(tcp_packets.at(i), false);
        }

        const struct ip* ipHeader = (struct ip*)(tcp_packets.at(i) + sizeof(struct ether_header));
        //std::cout << "Malloc = " << ntohs(ipHeader->ip_len)+sizeof(struct ether_header) << endl;
        const unsigned char *reassembled_packet = (const unsigned char*) malloc(ntohs(ipHeader->ip_len)+sizeof(struct ether_header));
        memcpy((unsigned char*)reassembled_packet, tcp_packets.at(i), ntohs(ipHeader->ip_len)+sizeof(struct ether_header));

        unsigned j = i;
        while (this->summary_length < this->dns_length) {
            if ( j == tcp_packets.size()-1) --j;

            const struct ether_header* ethernetHeader = (struct ether_header*)tcp_packets.at(j+1);

            u_char* payload = nullptr;

            if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
                payload = this->parse_IPv4_tcp_packet(tcp_packets.at(++j), true);
            }
            else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IPV6) {
                payload = this->parse_IPv6_tcp_packet(tcp_packets.at(++j), true);
            }

            if (payload) {
                //std::cout << std::dec << "PACKET = " << this->last_packet_length << " SEGMENT = " << this->tcp_segment_length << endl;
                tcp_packets.erase(tcp_packets.begin()+j);
                //i++;
                //std::cout << "Realloc = " << this->last_packet_length+this->tcp_segment_length << endl;
                reassembled_packet = (const unsigned char*) realloc((unsigned char*)reassembled_packet, (this->tcp_segment_length+this->last_packet_length));
                //std::cout << "AFTER" << endl;
                memcpy((unsigned char*)reassembled_packet+this->last_packet_length, payload, this->tcp_segment_length);
                this->last_packet_length += this->tcp_segment_length;
                //strcat((char*)reassembled_packet, (const char*)payload);
                //std::cout << "LEN = " << strlen((const char*)reassembled_packet) << endl;
                //std::cout << std::hex << setw(2) << (unsigned short)(reassembled_packet[3294-68] & 0xFF) << endl;
            }
        }
        //std::cout << std::hex << setw(2) << (unsigned short)(reassembled_packet[6] & 0xFF) << endl;

        reassembled_tcp_packets.push_back(reassembled_packet);
        this->summary_length = 0;
    }

    return reassembled_tcp_packets;
}

//this->tcp_segment_length = ntohs(ipHeader->ip_len) - ipHeader->ip_hl*4 - tcpHeader->th_off*4;
//this->tcp_segment_length = ntohs(ipv6pHeader->ip6_ctlun.ip6_un1.ip6_un1_plen) - offset - tcpHeader->th_off*4;

/*const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
uint16_t tcp_segment_length = ntohs(ipHeader->ip_len) - ipHeader->ip_hl*4 - tcpHeader->th_off*4;
std::cout << std::hex << ntohs(ipHeader->ip_id) << endl;
std::cout << std::dec;
std::cout << "TCP SEGMENT LENGTH = " << tcp_segment_length << endl;
std::cout << "SEQUENCE NUMBER = " << ntohl(tcpHeader->seq) << endl;
std::cout << "NEXT_SEQUENCE_NUMBER = " << tcp_segment_length + ntohl(tcpHeader->seq) << endl;
std::cout << "LENGTH = " << ntohs(dns_header->length) << endl;
std::cout << "----------------" << endl;
return;*/