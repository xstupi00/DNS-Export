/**************************************************************
 * Project:     DNS Export
 * File:		TCPReassembler.cpp
 * Author:		Šimon Stupinský
 * University: 	Brno University of Technology
 * Faculty: 	Faculty of Information Technology
 * Course:	    Network Applications and Network Administration
 * Date:		28.09.2018
 * Last change:	16.11.2018
 *
 * Subscribe:	The main module of TCPReassembler for executing the reassembling of TCP Packets.
 *
 **************************************************************/

/**
 * @file    TCPReassembler.cpp
 * @brief   This module implements methods from the TCPReassembler class, which are required to executing reassembling
 *          of TCP packets.
 */


#include "TCPReassembler.h"


/**
* TCPReassembler Contructor.
*/
TCPReassembler::TCPReassembler(size_t link_header_length) {
    this->datalink_header_length = link_header_length;
}


/**
* Default Destructor.
*/
TCPReassembler::~TCPReassembler() = default;


unsigned char *TCPReassembler::parse_transport_protocol(const unsigned char *packet, size_t offset, u_int8_t protocol,
                                                        bool tcp_parse) {
    unsigned char *payload = nullptr;

    ///< check correct access to the memory from that will be reading and the valid value of transport protocol
    if (protocol == IPPROTO_TCP and
        std::addressof(packet) + offset + sizeof(struct tcphdr) <= this->end_addr) {
        ///< obtaining the TCP Header
        const struct tcphdr *tcp_header = (struct tcphdr *) (packet + offset);
        ///< computing TCP Header Length
        size_t th_off = tcp_header->th_off << FOUR_OCTET_UNIT_TO_BYTES;

        ///< check the non-zero length of TCP Segment Length and correct access to the memory
        if (!tcp_parse and this->network_payload_len - th_off) {    ///< tcp_parse = 0
            if (std::addressof(packet) + offset + th_off <= this->end_addr) {
                ///< store the individual values required at reassembling
                this->tcp_sequence_number = ntohl(tcp_header->th_seq);
                this->tcp_segment_length = this->network_payload_len - th_off;
                ///< obtaining DNS Payload
                payload = (unsigned char *) (packet + offset + th_off);
                ///< obtaining the specific DNS PAYLOAD LENGTH value occurs only in TCP&DNS
                this->dns_length = ntohs(*((unsigned short *) payload));
                ///< store the individual values required at reassembling
                this->last_packet_length = this->total_len;
                this->packet_hdr_len = offset + th_off;
                payload += sizeof(unsigned short);
            }
        } else if (this->network_payload_len - th_off) {            ///< tcp_parse = 1
            ///< check the valid sequence of the sequence number of the actual packet and the last processing packet
            if (ntohl(tcp_header->th_seq) % INT_RANGE == (this->tcp_sequence_number + tcp_segment_length) % INT_RANGE) {
                ///< check correct access to the memory
                if (std::addressof(packet) + offset + th_off <= this->end_addr) {
                    ///< store the individual values required at reassembling
                    this->tcp_sequence_number = ntohl(tcp_header->th_seq);
                    this->tcp_segment_length = this->network_payload_len - th_off;
                    ///< obtaining DNS Payload
                    payload = (unsigned char *) (packet + offset + th_off);
                }
            }
        }
        ///< the summary length of the reassembled packet
        this->summary_length += tcp_segment_length;
    }

    return payload;
}

std::vector<std::pair<const unsigned char *, const unsigned char **>>
TCPReassembler::reassembling_packets(
        std::vector<std::tuple<const unsigned char *, const unsigned char **, bool>> *tcp_packets) {

    std::vector<std::pair<const unsigned char *, const unsigned char **>> reassembled_tcp_packets;

    for (std::tuple<const unsigned char *, const unsigned char **, bool> &tcp_packet : *tcp_packets) {
        if (std::get<2>(tcp_packet)) continue;
        this->end_addr = std::get<1>(tcp_packet);
        unsigned char *payload = this->my_pcap_handler(std::get<0>(tcp_packet));

        if (payload) {
            if (std::addressof(std::get<0>(tcp_packet)) + this->total_len <= this->end_addr) {
                auto reassembled_packet = (const unsigned char *) malloc(this->total_len);
                if (reassembled_packet == nullptr) {
                    std::perror("malloc() failed: ");
                    exit(EXIT_FAILURE);
                }
                memcpy((unsigned char *) reassembled_packet, std::get<0>(tcp_packet), this->total_len);

                auto j = (unsigned int) distance(&tcp_packets->at(0), &tcp_packet) + 1; ///< in-order byte stream
                while (this->summary_length < this->dns_length && j < tcp_packets->size()) {
                    if (std::get<2>((*tcp_packets).at(j))) {
                        j++;
                        continue;
                    }

                    this->end_addr = std::get<1>((*tcp_packets).at(j));
                    payload = this->my_pcap_handler(std::get<0>((*tcp_packets).at(j)), true);

                    if (payload and
                        std::addressof(payload) + this->tcp_segment_length <= (unsigned char **) this->end_addr) {
                        std::get<2>((*tcp_packets).at(j)) = true;
                        reassembled_packet = (const unsigned char *) realloc((unsigned char *) reassembled_packet,
                                                                             (this->tcp_segment_length +
                                                                              this->last_packet_length));
                        if (reassembled_packet == nullptr) {
                            std::perror("malloc() failed: ");
                            exit(EXIT_FAILURE);
                        }
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
                    std::get<2>(tcp_packet) = true;
                    reassembled_tcp_packets.push_back(packet_info);
                }
                this->summary_length = 0;
            }
        }
    }

    for (unsigned i = 0; i < tcp_packets->size(); i++) {
        if (std::get<2>(tcp_packets->at(i))) {
            tcp_packets->erase(tcp_packets->begin() + i);
            i--;
        }
    }

    return reassembled_tcp_packets;
}
