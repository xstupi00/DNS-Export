#include "TCPReassembler.h"


/**
* Default Contructor.
*/
TCPReassembler::TCPReassembler() = default;


/**
* Destructor.
*/
TCPReassembler::~TCPReassembler() = default;


unsigned char *TCPReassembler::parse_transport_protocol(const unsigned char *packet, unsigned offset, u_int8_t protocol,
                                                        bool tcp_parse) {

    unsigned char *payload = nullptr;
    int total = 0;

    if (std::addressof(packet) + sizeof(struct ether_header) <= this->end_addr) {
        const struct ether_header *ethernet_header = (struct ether_header *) packet;

        if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
            if (std::addressof(packet) + sizeof(struct ether_header) + sizeof(struct ip) <= this->end_addr) {
                const struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
                total = ntohs(ip_header->ip_len);
            }
        } else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IPV6) {
            if (std::addressof(packet) + sizeof(struct ether_header) + sizeof(struct ip6_hdr) <= this->end_addr) {
                const struct ip6_hdr *ipv6_header = (struct ip6_hdr *) (packet + sizeof(struct ether_header));
                total = ntohs(ipv6_header->ip6_plen);
            }
        }

        if (protocol == IPPROTO_TCP and
            std::addressof(packet) + sizeof(struct ether_header) + offset + sizeof(struct tcphdr) <= this->end_addr) {
            const struct tcphdr *tcp_header = (struct tcphdr *) (packet + sizeof(struct ether_header) + offset);

            if (!tcp_parse) {
                if (std::addressof(packet) + sizeof(struct ether_header) + offset +
                    (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES) <= this->end_addr) {
                    this->tcp_sequence_number = ntohl(tcp_header->th_seq);
                    this->tcp_segment_length = total - offset - (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES);
                    payload = (unsigned char *) (packet + sizeof(struct ether_header) + offset +
                                                 (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES));
                    auto length = (unsigned short *) payload;
                    payload += sizeof(unsigned short);
                    this->dns_length = ntohs(*length);
                    this->last_packet_length = total + sizeof(struct ether_header);
                    this->packet_hdr_len =
                            sizeof(struct ether_header) + offset + (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES);
                }
            } else {
                if (ntohl(tcp_header->th_seq) == this->tcp_sequence_number + tcp_segment_length) {
                    if (std::addressof(packet) + sizeof(struct ether_header) + offset +
                        (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES) <= this->end_addr) {
                        this->tcp_sequence_number = ntohl(tcp_header->th_seq);
                        this->tcp_segment_length = total - offset - (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES);
                        payload = (unsigned char *) (packet + sizeof(struct ether_header) + offset +
                                                     (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES));
                    }
                }
            }
            this->summary_length += tcp_segment_length;
        }
    }

    return payload;
}

std::vector<std::pair<const unsigned char *, const unsigned char **>>
TCPReassembler::reassembling_packets(
        std::vector<std::pair<const unsigned char *, const unsigned char **>> tcp_packets) {

    unsigned char *payload = nullptr;
    std::vector<std::pair<const unsigned char *, const unsigned char **>> reassembled_tcp_packets;

    for (std::pair<const unsigned char *, const unsigned char **> &tcp_packet : tcp_packets) {
        this->end_addr = tcp_packet.second;

        if (std::addressof(tcp_packet.first) + sizeof(struct ether_header) <= this->end_addr) {
            const struct ether_header *ethernet_header = (struct ether_header *) tcp_packet.first;

            if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
                payload = this->parse_IPv4_packet(tcp_packet.first, false);
            } else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IPV6) {
                payload = this->parse_IPv6_packet(tcp_packet.first, false);
            }

            if (payload) {
                const struct ip *ipHeader = (struct ip *) (tcp_packet.first + sizeof(struct ether_header));

                if (std::addressof(tcp_packet.first) + ntohs(ipHeader->ip_len) + sizeof(struct ether_header) <=
                    this->end_addr) {

                    auto reassembled_packet = (const unsigned char *) malloc(
                            ntohs(ipHeader->ip_len) + sizeof(struct ether_header));
                    memcpy((unsigned char *) reassembled_packet, tcp_packet.first,
                           ntohs(ipHeader->ip_len) + sizeof(struct ether_header));

                    auto j = (unsigned int) distance(&tcp_packets[0], &tcp_packet) + 1;///< in-order byte stream
                    while (this->summary_length < this->dns_length && j < tcp_packets.size()) {
                        this->end_addr = tcp_packets.at(j).second;

                        if (std::addressof(tcp_packets.at(j).first) + sizeof(struct ether_header) <= this->end_addr) {
                            const struct ether_header *ether_header = (struct ether_header *) tcp_packets.at(j).first;

                            if (ntohs(ether_header->ether_type) == ETHERTYPE_IP) {
                                payload = this->parse_IPv4_packet(tcp_packets.at(j).first, true);
                            } else if (ntohs(ether_header->ether_type) == ETHERTYPE_IPV6) {
                                payload = this->parse_IPv6_packet(tcp_packets.at(j).first, true);
                            }

                            if (payload and
                                std::addressof(payload) + this->tcp_segment_length <=
                                (unsigned char **) this->end_addr) { ///< found the required ACK_NUMBER
                                tcp_packets.erase(tcp_packets.begin() + j);
                                reassembled_packet = (const unsigned char *) realloc(
                                        (unsigned char *) reassembled_packet,
                                        (this->tcp_segment_length +
                                         this->last_packet_length));
                                memcpy((unsigned char *) reassembled_packet + this->last_packet_length, payload,
                                       this->tcp_segment_length);
                                this->last_packet_length += this->tcp_segment_length;
                            } else {      ///< don't found the required ACK_NUMBER, will continue on the next packet
                                j++;
                            }
                        }
                    }

                    std::pair<const unsigned char *, const unsigned char **> packet_info = std::make_pair(
                            reassembled_packet,
                            std::addressof(reassembled_packet) + this->packet_hdr_len + this->dns_length);
                    if (this->summary_length >= this->dns_length) {
                        reassembled_tcp_packets.push_back(packet_info);
                    }
                    this->summary_length = 0;
                }
            }
        }
    }

    return reassembled_tcp_packets;
}
