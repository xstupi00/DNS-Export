/**************************************************************
 * Project:     DNS Export
 * File:		TCPReassembler.h
 * Author:		Šimon Stupinský
 * University: 	Brno University of Technology
 * Faculty: 	Faculty of Information Technology
 * Course:	    Network Applications and Network Administration
 * Date:		28.09.2018
 * Last change:	16.11.2018
 *
 * Subscribe:	The header module of TCPReassembler for executing the reassembling of TCP Packets.
 *
 **************************************************************/

/**
 * @file    TCPReassembler.h
 * @brief   This module contains the definitions of attributes and methods from the TCPReassembler class, which are
 *          required to executing reassembling of TCP packets.
 */

#ifndef TCPREASSEMBLER_H
#define TCPREASSEMBLER_H

#include <cstring>
#include <iomanip>
#include <netinet/ip6.h>
#include <netinet/ip.h>

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef NETINET_TCP_H
#include <netinet/tcp.h>
#define NETINET_TCP_H
#endif

#include "DnsExport.h"

///< value for computing the TCP SEQUENCE NUMBER
#define INT_RANGE 1UL<<32

/**
 * TCPReassembler class for reassembling TCP Packets
 */
class TCPReassembler : public DnsExport {
public:
    /**
     * @brief Default constructor declaration
     *
     * @param link_header_length
     */
    TCPReassembler(size_t link_header_length);

    ///< Default constructor declaration
    ~TCPReassembler();

    ///< tcp segment length represents the handy data in the packet
    size_t tcp_segment_length = 0;
    ///< tcp sequence number identify the individual packets from the concrete tcp communication
    unsigned int tcp_sequence_number;
    ///< length of DNS Payload obtained from the first packet from the sequence of the reassembling (first 2 bytes)
    size_t dns_length;
    ///< summary length during the reassembling tcp packets insure the finish condition
    size_t summary_length = 0;
    ///< value required at realloc of the size the result reassembled packet at adding the next part od DNS payload
    size_t last_packet_length = 0;
    ///< packet headers length obtained from the first packet from the sequence of the reassembling (sum of its headers)
    size_t packet_hdr_len = 0;

    /**
     * @brief   Method executing the reassembling of the TCP packets. The main logic of reassembling is too complex for
     *          explanation here and because will be deta redddil described in the Project Documentation.
     *
     * @param tcp_packets   vector that contains caught TCP packets to reassembling
     *
     * @return  method return the vector with reassembled packets ready to parse of DNS payload
     */
    std::vector<std::pair<const unsigned char *, const unsigned char **>>
    reassembling_packets(std::vector<std::tuple<const unsigned char *, const unsigned char **, bool>> *tcp_packets);

    /**
     * @brief   The method that executing the parsing of the transport layer, so the TCP Header at reassembling the TCP packets.
     *          In the case when the tcp_parse is turn off (tcp_parse = 0) are stored the all required values to
     *          class attributes and DNS Payload is returned. In the case, when tcp_parse flag is on (tcp_parse = 1)
     *          is checked the valid values of sequence numbers according to required conditions and following are stored
     *          new sequence number and segment length to class attributes, DNS Payload is returned too.
     *
     * @param packet    Pointer at the begin of the caught packet
     * @param offset    Offset from the begin of the packet to the begin of transport header
     * @param protocol  Value of the transport protocol (UDP = 6, TCP = 17)
     * @param tcp_parse Auxiliary flag for differentiation parse or store the TCP Packets
     *
     * @return
     */
    unsigned char *
    parse_transport_protocol(const unsigned char *packet, size_t offset, u_int8_t protocol, bool tcp_parse) override;
};

#endif //TCPREASSEMBLER_H
