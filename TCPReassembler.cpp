#include <iomanip>
#include "TCPReassembler.h"


/**
* Default Contructor.
*/
TCPReassembler::TCPReassembler(int link_type) {
    this->link_type = link_type;
}


/**
* Destructor.
*/
TCPReassembler::~TCPReassembler() = default;


unsigned char *TCPReassembler::parse_transport_protocol(const unsigned char *packet, size_t offset, u_int8_t protocol,
                                                        bool tcp_parse) {
    unsigned char *payload = nullptr;

    if (protocol == IPPROTO_TCP and
        std::addressof(packet) + offset + sizeof(struct tcphdr) <= this->end_addr) {
        const struct tcphdr *tcp_header = (struct tcphdr *) (packet + offset);

        if (!tcp_parse) {
            if (std::addressof(packet) + offset + (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES) <= this->end_addr) {
                this->tcp_sequence_number = ntohl(tcp_header->th_seq);
                this->tcp_segment_length = this->ip_total_len - offset - (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES);
                payload = (unsigned char *) (packet + offset + (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES));
                auto length = (unsigned short *) payload;
                payload += sizeof(unsigned short);
                this->dns_length = ntohs(*length);
                this->last_packet_length = this->ip_total_len;
                this->packet_hdr_len = offset  + (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES);
            }
        } else {
            if (ntohl(tcp_header->th_seq) == this->tcp_sequence_number + tcp_segment_length) {
                if (std::addressof(packet) + offset +
                    (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES) <= this->end_addr) {
                    this->tcp_sequence_number = ntohl(tcp_header->th_seq);
                    this->tcp_segment_length = this->ip_total_len - offset - (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES);
                    payload = (unsigned char *) (packet + offset +
                                                 (tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES));
                }
            }
        }
        this->summary_length += tcp_segment_length;
    }

    return payload;
}

std::vector<std::pair<const unsigned char *, const unsigned char **>>
TCPReassembler::reassembling_packets(
        std::vector<std::pair<const unsigned char *, const unsigned char **>> tcp_packets) {

    std::vector<std::pair<const unsigned char *, const unsigned char **>> reassembled_tcp_packets;

    for (std::pair<const unsigned char *, const unsigned char **> &tcp_packet : tcp_packets) {
        this->end_addr = tcp_packet.second;
        unsigned char *payload = this->my_pcap_handler(tcp_packet.first, false);

        if (payload) {
            if (std::addressof(tcp_packet.first) + this->ip_total_len <= this->end_addr) {

                auto reassembled_packet = (const unsigned char *) malloc(this->ip_total_len);
                memcpy((unsigned char *) reassembled_packet, tcp_packet.first, this->ip_total_len);

                auto j = (unsigned int) distance(&tcp_packets[0], &tcp_packet) + 1;///< in-order byte stream
                while (this->summary_length < this->dns_length && j < tcp_packets.size()) {
                    this->end_addr = tcp_packets.at(j).second;
                    payload = this->my_pcap_handler(tcp_packets.at(j).first, true);

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

    return reassembled_tcp_packets;
}
