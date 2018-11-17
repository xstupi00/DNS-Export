/**************************************************************
 * Project:     DNS Export
 * File:		DnsExport.h
 * Author:		Šimon Stupinský
 * University: 	Brno University of Technology
 * Faculty: 	Faculty of Information Technology
 * Course:	    Network Applications and Network Administration
 * Date:		28.09.2018
 * Last change:	16.11.2018
 *
 * Subscribe:	The header module of DnsExport class, that represents the main logic of whole application
 *
 **************************************************************/

/**
 * @file    ArgumentParser.h
 * @brief   Declaration of methods and attributes for DnsExport class, in that is executing the main logic, that is
 *          needed at running the application. This header module contains the definitions of constants, which
 *          doesn't defined in built-in headers module.
 */

#ifndef DNSEXPORT_H
#define DNSEXPORT_H

#include <algorithm>
#include <csignal>
#include <pcap.h>
#include <unistd.h>
#include <unordered_map>

#include "ArgumentsParser.h"
#include "DataStructures.h"

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef NETINET_TCP_H

#include <netinet/tcp.h>

#define NETINET_TCP_H
#endif

/*
 * Definitions of the DNS Resource Records Types that are processing in this application.
 */
#define DNS_ANS_TYPE_A          1   ///< A Resource Record (IPv4)
#define DNS_ANS_TYPE_NS         2   ///< NS Resource Record (NameServer)
#define DNS_ANS_TYPE_CNAME      5   ///< CNAME Resource Record (CanonicalNAME)
#define DNS_ANS_TYPE_SOA        6   ///< SOA Resource Record (Start Of Authority)
#define DNS_ANS_TYPE_PTR        12  ///< PTR Resource Record (Pointer)
#define DNS_ANS_TYPE_MX         15  ///< MX Resource Record (Mail Exchange)
#define DNS_ANS_TYPE_TXT        16  ///< TXT Resource Record (TeXT)
#define DNS_ANS_TYPE_AAAA       28  ///< AAAA Resource Record (IPv6)
#define DNS_ANS_TYPE_SRV        33  ///< SRV Resource Record (SeRVice)
#define DNS_ANS_TYPE_DS         43  ///< DS Resource Record (Delegation Signer)
#define DNS_ANS_TYPE_RRSIG      46  ///< RRSIG Resource Record (RRset Signature)
#define DNS_ANS_TYPE_NSEC       47  ///< NSEC Resource Record (Next Secure)
#define DNS_ANS_TYPE_DNSKEY     48  ///< DNSKEY Resource Record (DNSSEC Public Key)
#define DNS_ANS_TYPE_NSEC3      50  ///< NSEC3 Resource Record (Next SECure v.3)
#define DNS_ANS_TYPE_NSEC3PARAM 51  ///< NSEC3PARAM Resource Record (NSEC3 PARAMeters)
#define DNS_ANS_TYPE_SPF        99  ///< SPF Resource Record (Sender Policy Framework)

/**
 * Definitions of IPv6 Extension Headers that will be skipping in the case of its occurance.
 */
#define NEXTHDR_HOP         0       ///< Hop-by-hop option header
#define NEXTHDR_IPV6        41      ///< IPv6 in IPv6
#define NEXTHDR_ROUTING     43      ///< Routing header
#define NEXTHDR_FRAGMENT    44      ///< Fragmentation/reassembly header
#define NEXTHDR_AUTH        51      ///< Authentication header
#define NEXTHDR_DEST        60      ///< Destination options header
#define NEXTHDR_MOBILITY    135     ///< Mobility header

/**
 * Definitions the constants needed at processing the DNS Packets
 */
#define FOUR_OCTET_UNIT_TO_BYTES    2   ///< Transformation the four-octet length field in the IPv6 Extension Headers
#define EIGHT_OCTET_UNIT_TO_BYTES   3   ///< Transformation the eight-octet length field in the IPv6 Extension Headers
#define UPPER_BYTE_HALF             4   ///< Auxiliary constant value for bites shift and obtains the upper half of byte
#define IP_HEADER_MIN_LEN           20  ///< The minimal required length of the IPv4 headers (network layer)
#define TCP_HEADER_MIN_LEN          32  ///< The minimal required length of the TCP headers (transport layer)
#define IPv6_HEADER_LEN             40  ///< The constant required length of the IPv6 basic Header (network layer)
#define IP_HEADER_MAX_LEN           60  ///< The maximum acceptable length of the IPv4 headers (network layer)
#define NETWORK_IPv4                4   ///< The value of the VERSION field in the IPv4 headers (network layer)
#define NETWORK_IPv6                6   ///< The value of the VERSION field in the IPv6 headers (network layer)

///< The definition of macro for ignoring the warning about the unused value in the signal handlers
#define UNUSED(x) (void)(x)

///< The definitions of chars needed to base64 coding
static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

///< The global variable for the applications statistics about the sniffing DNS Traffic
extern std::unordered_map<std::string, int> stats;

/**
 * @brief   Handler for expiration of alarm that running for given period. The main functionality of function is secures
 *          the sending the stats to syslog message. Function fork the main process and it will continue back to own
 *          processing. The child process secure the send stats to given syslog servers.
 *
 * @param _ unused ID of handled signal
 *
 * @return function has no return value
 */
extern void handle_alarm_signal(int _);

/**
 * @brief   Handler for SIGUSR1 Signal that indicates requirement of user to writing the actual processing stats on
 *          stdout. The main functionality is only printing stats on stdout. Function fork the main process and it will
 *          continue back to own processing, child process secure printing.
 *
 * @param _ unused ID of handled signal
 *
 * @return function has no return value
 */
extern void handle_sigusr_signal(int _);


/**
 * DnsExport class for executing the main logic of whole application
 */
class DnsExport {
public:
    ///< Default constructor declaration
    DnsExport();

    ///< Default destructor declaration
    ~DnsExport();

    ///< vector to collect the receving TCP Packets and to its following processing
    std::vector<std::tuple<const unsigned char *, const unsigned char **, bool>> tcp_packets;
    ///< vector to collect the DNS_ID from the DNS Queries and to its following checking with the IDs from DNS Answers
    std::vector<uint16_t> dns_ids;
    ///< the value in the memory, where has the packet the last allocated memory cell for checking the allowed access
    const unsigned char **end_addr;
    ///< the length of the datalink header in the actual processing packet
    size_t datalink_header_length;
    ///< the length of the whole actual processing packet, needed at reassembling TCP packets
    size_t total_len = 0;
    ///< the length of the network payload computed from the fields in the IPv4, respectively IPv6 Headers
    size_t network_payload_len = 0;

    /**
     * @brief   The method that represents the wrapper for the whole application.Only this method is free accessible
     *          out of Class (public methods).Method represents the brain of application, because for the executing
     *          the program is enough call it from the main function of the program and this method secures the all
     *          needed steps.
     *
     * @param argc  count of the arguments
     * @param argv  array with the arguments
     *
     * @return  method has no return value
     */
    void run(int argc, char **argv);

    /**
     * @brief   Method that secures the reassembling of the TCP packets and then its processing to the statistics of
     *          DNS traffic. The method on its own don't have some special functionality, but only calling the another
     *          methods for executing the needed actions.
     *
     * @param   method has no parameters
     * *
     * @return  method has no return value
     */
    void proccess_tcp_packets();

    /**
     * @brief   Method that have responsibility about the first step in the processing of caught packet.
     *          Method that according to type of the datalink header skip this header and then according to the first
     *          byte after datalink header distinguish the type of header in the network layer.
     *
     * @param packet    caught packet (read from the .pcap file or caught on the given interface)
     * @param tcp_parse flag to store TCP packets to the vector (0), respectively to parse TCP packets (1)
     *
     * @return  method returns DNS PAYLOAD after the processing and skipping all layers headers
     */
    unsigned char *my_pcap_handler(const unsigned char *packet, bool tcp_parse = false);

private:

    /**
     * @brief   Method that executing the reading and backward transformation of the domain name from the DNS
     *          compression.In the first part of method is reading the name from the DNS format with label and in
     *          the second phase transform this name to form of normal way.
     *
     * @param reader    Pointer to actual position in the receiving packet
     * @param buffer    Pointer at the begin of the receiving packet
     * @param count     Index for the following shift in the buffer after the reading domain name
     *
     * @return  transformed name in the form of normal way (no DNS compression -> no label from)
     */
    std::string read_name(unsigned char *reader, unsigned char *buffer, unsigned *count);

    /**
     * @brief   Method that parsing DNS Payloads.
     *          If is the DNS Payload of type DNS Query, then method store the ID to the vector of IDs.
     *          If is the DNS Paylaod of type DNS Answer and the ID of this answer is stored in the vector of IDs, then
     *          method skipping the Queries Array and will parsing the individual answer from Answers array.
     *          After the successful parse of DNS Payload from the DNS Answers array will be obtained information
     *          saved to the statistics map.
     *
     * @param payload   DNS Payload to parse and saved the Answers to the statistics map
     * @param tcp       Auxiliary flag for differentiation TCP DNS Payload and skipping the first two bytes, that
     *                  contains the length of DNS Payload (in UDP DNS Payload is not present).
     *
     * @return  method has no return value
     */
    void parse_payload(unsigned char *payload, bool tcp);

    /**
     * @brief   Method that parsing individual Resource Records from the DNS Payload (Answer Array).
     *          According to type of individual Resource Records will executing transformation to needed form
     *          defined in the RFC, where is this RR type described. In the case, when come the unknown RR type will
     *          be only skipped.
     *
     * @param record_type       Value of Resource Record Type (see defined in header file)
     * @param record_length     Length of the given Resource Record obtained from its header (RDLENGTH)
     * @param record_payload    DNS Payload to parse
     * @param buffer            Pointer at the begin of the parsed packet for control the shift in the memory
     *
     * @return  methods returns the formatted string according to requirements of statistics listing
     */
    std::string
    decode_dns_record(int record_type, unsigned record_length, unsigned char *record_payload, unsigned char *buffer);

    void proccess_next_header(const unsigned char *ipv6_header, uint8_t *next_header, unsigned *offset);

    /**
     * @brief   Method that executing the parsing of the IPv4 header in the network layer, executing the control of
     *          acceptable length of this header and store the needed fields to follows processing.
     *
     * @param packet    Pointer at the begin of the caught packet
     * @param tcp_parse Forwarding the flag to store or parse of TCP packets
     *
     * @return  method returns DNS PAYLOAD processed by the methods, that processing the headers of the higher layers
     */
    unsigned char *parse_IPv4_packet(const unsigned char *packet, bool tcp_parse = false);

    /**
     * @brief   Method that executing the parsing of the IPv6 header in the network layer, executing the control of
     *          acceptable length of this header and store the needed fields to follows processing. In the case
     *          of presence the Extension Headers secures the its processing, respectively its skipping.
     *
     * @param packet    Pointer at the begin of the caught packet
     * @param tcp_parse Forwarding the flag to store or parse of TCP packets
     *
     * @return  method returns DNS PAYLOAD processed by the methods, that processing the headers of the higher layers
     */
    unsigned char *parse_IPv6_packet(const unsigned char *packet, bool tcp_parse = false);

    /**
     * @brief   Method that executing the parsing of the TCP and UDP headers in the transport layer.
     *          In the case of TCP Header is control the minimal length of this header. In the next step is control the
     *          TCP Segment Length, that must be greater than 0. After the successful control according to tcp_parse
     *          flag are executing two situations. In the case when the tcp_parse is on (tcp_parse == 1) is obtained
     *          the DNS payload which will returns from method. If the tcp_parse is off (tcp_parse == 0) then is the
     *          whole packet stored to the vector of TCP Packets and suspended to later processing.
     *          In the case of UDP Header is only obtained DNS Payload for return value of method.
     *
     * @param packet    Pointer at the begin of the caught packet
     * @param offset    Offset from the begin of the packet to the begin of transport header
     * @param protocol  Value of the transport protocol (UDP = 6, TCP = 17)
     * @param tcp_parse Auxiliary flag for differentiation parse or store the TCP Packets
     *
     * @return  method returns DNS payload in the case, when the tcp_flag is on, else return the nullptr for
     *          differentiation the store of TCP packets
     */
    virtual unsigned char *
    parse_transport_protocol(const unsigned char *packet, size_t offset, u_int8_t protocol, bool tcp_parse);

    /**
     * @brief   Method executing the transformation of time, that is present in the DNS Resource Records to the form
     *          given of the presentation format in the RFC according to concrete RR Type.
     *
     * @param   utc_time Time in UTC format in the format from answer
     *
     * @return  method returns the UTC time in the required format according to RFC
     */
    char *transform_utc_time(uint32_t utc_time);

    /**
     * @brief   Method executing the processing of Bit Maps in the NSEC RR Type and NSEC3 RR Type. This Bit Maps is
     *          represented as a sequence of RR type mnemonics, respectively its value of RR Type on the relevant
     *          position in the individual bits of array.
     *
     * @param   record_payload Pointer to field contains the length of Bit Maps in bytes
     *
     * @return  method returns the string that contains the sequence of RR Type mnemonics
     */
    std::string proccess_bits_array(unsigned char *record_payload);

    /**
     * @brief   Method that starting sniffing on the given interface in the online mode or open the pcap file for
     *          parsing in the offline mode. Method after the start sets the capture filter for packets, in the our
     *          case for DNS Packets. In the next step obtained the length od datalink header from the every packet
     *          and call the relevant methods for its processing.
     *
     * @param name  name with the interface name in the online mode or with the filename in offline mode
     * @param mode  0 for offline mode (pcap file), 1 for online mode (interface sniffing)
     *
     * @return method has no return value
     */
    void execute_sniffing(const char *name, bool mode = false);

    /**
     * @brief   Method encode given bytes to the format base_64. This format is required by RRSIG RR Type in the
     *          signature field and by DNSKEY RR Type in the public key field.
     *
     * @param bytes_to_encode   bytes that will be encoded to the base_64
     * @param in_len            length og the bytes, that will be encoded
     *
     * @return  string in the base_64 format (encoded bytes in the base_64)
     */

    /***************************************************************************************
    *    Title: Encoding and decoding base 64 with c++
    *    Author: 2004-2017 René Nyffenegger
    *    Project: cpp-base64
    *    Version: 1.01.00
    *    Date: 07.11.2018
    *    Availability: https://github.com/ReneNyffenegger/cpp-base64/blob/master/base64.cpp#L45
    *
    ***************************************************************************************/
    std::string base64_encode(unsigned char const *bytes_to_encode, unsigned int in_len);
};

#endif //DNSEXPORT_H
