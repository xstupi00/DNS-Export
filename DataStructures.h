/**************************************************************
 * Project:     DNS Export
 * File:		DataStructures.h
 * Author:		Šimon Stupinský
 * University: 	Brno University of Technology
 * Faculty: 	Faculty of Information Technology
 * Course:	    Network Applications and Network Administration
 * Date:		28.09.2018
 * Last change:	16.11.2018
 *
 * Subscribe:	The module that contains the definitions of needed data structures
 *
 **************************************************************/

/**
 * @file    DataStructures.h
 * @brief   This module define the needed data structures for processing of IPv6 extension headers
 *          and data structured needed for proccessing DNS Resource Records. Also contains three another
 *          auxiliary declarations of methods, that working with content of these structures.
 */

/**
 * @brief   Method to decode the Resource Record (RR) TYPEs.
 *          The reference sources of the types were the [RFC689][RFC1035]
 *          (the closer info in the  Project Documentation)
 *
 * @param rr_type   Resource Record TYPE
 *
 * @return  method returns the Resource Recors Type mnemomic name
 */
std::string decode_rr_type(int rr_type);

/**
 * @brief   Method to decode the DNS Security Algorithm Numbers.
 *          The reference sources of the types were the [RFC4034][RFC3755][RFC6014][RFC6944]
 *          (the closer info in the  Project Documentation)
 *
 * @param algorithm DNS Security Algorithm number
 *
 * @return  method returns an algorithm mnemomic name
 */
std::string decode_algorithm(int algorithm);

/**
 * @brief   Method for obtaining the relevant length of the datalink header.
 *
 * @param   datalink_id ID of datalink header
 *
 * @return  method returns the relevant length according to ID and the actual OS system
 */

/***************************************************************************************
*    Title: The Nmap Security Scanner
*    Author: 1996-2018 Insecure.Com LLC
*    Project: The Nmap Project
*    Date: 01.11.2018
*    Availability: https://github.com/nmap/nmap/blob/6a42ef47c08c7a450cefb543fe028bcf991f00b6/tcpip.cc#L1552
*
***************************************************************************************/
size_t get_length_of_datalink(int datalink_id);

/**
 * UDP transport-layer header
 */
struct udp_hdr {
    uint16_t source;    ///< identifies the sender's port
    uint16_t dest;      ///< identifies the receiver's port
    uint16_t length;    ///< length in bytes of the UDP header and UDP data
    uint16_t checksum;  ///< checksum used for error-checking of the header and data
};

/**
 * The Authentication IPv6 Extension Header
 */
struct auth_hdr {
    uint8_t ip6h_nxt;   ///< next header
    uint8_t ip6h_len;   ///< length in units of 8 octets
    uint16_t ip6h_res;  ///< reserved 2 bytes
    uint32_t ip6h_spi;  ///< security parameters index
    ///< followed by 32-bits sequence number
    ///< followed by authentication data with variable length
};

/**
 * The Hop-By-Hop Options IPv6 Extension Header
 */
struct ipv6_hbh {
    uint8_t ip6h_nxt;   ///< next header
    uint8_t ip6h_len;   ///< length in units of 8 octets
    uint16_t ip6h_opt;  ///< options
    uint32_t ip6h_pad;  ///< padding
    ///< can be followed by more options and padding
};

/**
 * The Destination Options IPv6 Extension Header
 */
struct ipv6_dest {
    uint8_t ip6d_nxt;   ///< next header
    uint8_t ip6d_len;   ///< length in units of 8 octets
    uint16_t ip6h_opt;  ///< options and padding
    uint32_t ip6h_pad;  ///< options and padding
    ///< can be followed by more options and padding
};

/**
 * The Routing IPv6 Extension Header
 */
struct ipv6_rthdr {
    uint8_t ip6r_nxt;   ///< next header
    uint8_t ip6r_len;   ///< length in units of 8 octets
    uint8_t ip6r_type;  ///< routing type
    uint8_t ip6r_seg;   ///< segments left
    uint32_t ip6r_data; ///< specific data
    ///< followed by routing type specific data
};

/**
 * The Mobility IPv6 Extension Header
 */
struct ipv6_mobility {
    uint8_t ip6m_nxt;       ///< next header
    uint8_t ip6m_len;       ///< length in units of 8 octets
    uint8_t ip6m_type;      ///< routing type
    uint8_t ip6m_reserve;   ///< reserving space
    uint16_t ip6m_checksum; ///< checksum
    uint16_t ip6m_data;     ///< mandatory size of the data
    ///< can be followed by more data
};


/**
 * Header of SOA Resource Record - Start of Authority
 */
struct soa_record {
    ///< Name of primary DNS server
    ///< E-mail address of responsible person
    uint32_t serial;    ///< The timestamp that changes whenever you update your domain
    uint32_t refresh;   ///< The number of seconds before the zone should be refreshed
    uint32_t retry;     ///< The number of seconds before a failed refresh should be retried
    uint32_t expire;    ///< The upper limit in seconds before a zone is considered no longer authoritative
    uint32_t min_ttl;   ///< The negative result TTL
};

/**
 * Header of RRSIG Resource Record - RRset Signature
 */
struct __attribute__((__packed__)) rrsig_record {
    uint16_t type_covered;  ///< DNS record type that this signature covers
    uint8_t algorithm;      ///< Cryptographic algorithm used to create the signature
    uint8_t labels;         ///< Number of labels in the original RRSIG-record name
    uint32_t orig_ttl;      ///< TTL value of the covered record set
    uint32_t signature_exp; ///< When the signature expires
    uint32_t signature_inc; ///< When the signature was created
    uint16_t key_tag;       ///< A short numeric value which can help quickly identify the DNSKEY-record
    ///< Signer's Name: Name of the DNSKEY-record which can be used to validate this signature
    ///< Signature: Cryptographic signature
};

/**
 * Header of DS Resource Record - Delegation Signer
 */
struct ds_record {
    uint16_t key_id;    ///< A short numeric value which can help quickly identify the referenced DNSKEY-record
    uint8_t algorithm;  ///< The algorithm of the referenced DNSKEY-record
    uint8_t digest_type;///< Cryptographic hash algorithm used to create the Digest value
    ///< Followed by cryptographic hash value of the referenced DNSKEY-record
};

/**
 * Header of SRV Resource Record - Location of Service
 */
struct srv_record {
    ///< Service: Most internet services are defined in RFC1700
    ///< Protocol: Generally TCP or UDP, but also values are also valid
    ///< Domain Name
    uint16_t priority;  ///< Preference number used when more servers are providing the same service
    uint16_t weight;    ///< Weight is used for advanced load balancing
    uint16_t port;      ///< Port is the TCP/UDP port number on the server that provides this service
};

/**
 * Header of NSEC3 Resource Record - Next Secure v.3
 */
struct __attribute__((__packed__)) nsec3_record {
    uint8_t algorithm;      ///< The cryptographic hash algorithm used
# if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t opt_out :1;     ///<  "Opt-out" (indicates if delegations are signed or not)
    uint8_t reserved :7;    ///<  Reserved for future times
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t reserved :7;
    uint8_t opt_out :1;
# endif
    uint16_t iterations;    ///< How many times the hash algorithm is applied
    uint8_t salt_length;    ///< Salt value for the hash calculation
    ///< Followed by the Record Types that exist for the name covered by the hash value
};


/**
 * Header of DNSKEY Resource Record - DNSSEC public key
 */
struct dnskey_record {
# if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t zone_key :1;        ///< set for all DNSSEC keys
    uint8_t a1 :7;              ///< reserved bits - must have value 0
    uint8_t key_signining :1;   ///<
    uint8_t a2 :6;              ///< reserved bits - must have value 0
    uint8_t key_revoked :1;     ///< Secure Entry Point
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t a1 :7;
    uint8_t zone_key :1;
    uint8_t key_revoked :1;
    uint8_t a2 :6;
    uint8_t key_signining :1;
# endif
    uint8_t protocol;           ///<  Fixed value of 3 (for backwards compatibility)
    uint8_t algorithm;          ///<  The public key's cryptographic algorithm
    ///< Followed by Public key data with variable length
};

/**
 * The structure contains all needed flags and other items for creating the head
 * of DNS messages for communication with the DNS server.
 */
struct DNS_HEADER {
    uint16_t ID;          ///< 16 bit identifier assigned by the program

# if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t RD :1;        ///< Recursion Desired
    uint8_t TC :1;        ///< TrunCation
    uint8_t AA :1;        ///< Authorirative Answer
    uint8_t OPCODE :4;    ///< 4 bit field that species kind of query
    uint8_t QR :1;        ///< Query or Response message

    uint8_t RCODE  :4;    ///< 4 bit field is set as part of responses
    uint8_t CD :1;        ///< Checking Disabled
    uint8_t AD :1;        ///< Authenticated Data
    uint8_t Z  :1;        ///< Reserved for the future use
    uint8_t RA :1;        ///< Recursion Available
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t QR :1;        ///< Query or Response message
    uint8_t OPCODE :4;    ///< 4 bit field that species kind of query
    uint8_t AA :1;        ///< Authorirative Answer
    uint8_t TC :1;        ///< TrunCation
    uint8_t RD :1;        ///< Recursion Desired

    uint8_t RA :1;        ///< Recursion Available
    uint8_t Z  :1;        ///< Reserver for the future use
    uint8_t AD :1;        ///< Authenticated Data
    uint8_t CD :1;        ///< Checking Disabled
    uint8_t RCODE  :4;    ///< 4 bit field is set as part of responses
# endif

    uint16_t QDCOUNT;     ///< number of entries in the question section.
    uint16_t ANCOUNT;     ///< number of resource records in the answer section.
    uint16_t NSCOUNT;     ///< number of name server resource records in the authority records section.
    uint16_t ARCOUNT;     ///< number of resource records in the additional records section
};

/**
 *The structure for definition the Question format used to carry the "question" in most queries.
 */
struct QUESTION_FORMAT {
    uint16_t QTYPE;       ///< two octet code which specifies the type of the query
    uint16_t QCLASS;      ///< two octet code that specifies the class of the query
};


/**
 * The structure for Resource record format. All sections (answer, authority, additional) share the same format.
 */
struct __attribute__((__packed__)) RESOURCE_FORMAT {
    uint16_t TYPE;        ///< two octets containing one of the RR type codes
    uint16_t CLASS;       ///< two octets which specify the class of the data in the RDATA field
    uint32_t TTL;         ///< a 32 bit unsigned integer that specifies the time interval (in seconds)
    uint16_t RDLENGTH;    ///< 16 bit integer that specifies the length in octets of the RDATA field
};
