#include <vector>

std::string decode_rr_type(int rr_type);

std::string decode_algorithm(int algorithm);

size_t get_size_of_datalink(int datalink_id);

struct AddressWrapper {
    std::vector<struct sockaddr_in> addr_IPv4;
    std::vector<struct sockaddr_in6> addr_IPv6;
};

struct __attribute__((__packed__)) linux_sll {
    uint16_t packet_type;
    uint16_t arphrd_type;
    uint16_t addr_length;
    uint64_t addr;
    uint16_t protocol_type;
};

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t length;
    uint16_t checksum;
};

struct auth_hdr {
    uint8_t ip6h_nxt;        /* next header.  */
    uint8_t ip6h_len;        /* length in units of 8 octets.  */
    uint16_t ip6h_res;      /* reserved 2 bytes */
    uint32_t ip6h_spi;      /* security parameters index */
    /* followed by 32-bits sequence number */
    /* followed by authentication data with variable length */
};

struct ipv6_hbh {
    uint8_t ip6h_nxt;        /* next header.  */
    uint8_t ip6h_len;        /* length in units of 8 octets.  */
    uint16_t ip6h_opt;      /* options and padding */
    uint32_t ip6h_pad;      /* options and padding */
    /* can be followed by more options and padding */
};

struct ipv6_dest {
    uint8_t ip6d_nxt;        /* next header */
    uint8_t ip6d_len;        /* length in units of 8 octets */
    uint16_t ip6h_opt;      /* options and padding */
    uint32_t ip6h_pad;      /* options and padding */
    /* can be followed by more options and padding */
};

struct ipv6_rthdr {
    uint8_t ip6r_nxt;        /* next header */
    uint8_t ip6r_len;        /* length in units of 8 octets */
    uint8_t ip6r_type;        /* routing type */
    uint8_t ip6r_segleft;    /* segments left */
    uint32_t ip6r_data;     /* specific data */
    /* followed by routing type specific data */
};

struct ipv6_mobility {
    uint8_t ip6m_nxt;        /* next header */
    uint8_t ip6m_len;        /* length in units of 8 octets */
    uint8_t ip6m_type;        /* routing type */
    uint8_t ip6m_reserve;  /* reserving space */
    uint16_t ip6m_checksum; /* checksum */
    uint16_t ip6m_data;     /* mandatory size of the data */
    /* can be followed by more data */
};

struct ns_preference {
    unsigned short preference;
};

struct soa_record {
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t min_ttl;
};

struct __attribute__((__packed__)) rrsig_record {
    uint16_t type_covered;
    uint8_t algorithm;
    uint8_t labels;
    uint32_t orig_ttl;
    uint32_t signature_exp;
    uint32_t signature_inc;
    uint16_t key_tag;
};

struct ds_record {
    uint16_t key_id;
    uint8_t algorithm;
    uint8_t digest_type;
};

struct srv_record {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
};

struct nsec_record {
    uint16_t bit_maps_count;
};

struct __attribute__((__packed__)) nsec3_record {
    uint8_t algorithm;
# if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t opt_out :1;
    uint8_t reserved :7;
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t reserved :7;
    uint8_t opt_out :1;
# endif
    uint16_t iterations;
    uint8_t salt_length;
}; // +1

struct dnskey_record {
# if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t zone_key :1;
    uint8_t a1 :7;
    uint8_t a2 :6;
    uint8_t key_revoked :1;
    uint8_t key_signining :1;
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t a1 :7;
    uint8_t zone_key :1;
    uint8_t key_signining :1;
    uint8_t key_revoked :1;
    uint8_t a2 :6;
# endif
    uint8_t protocol;
    uint8_t algorithm;
};

/**
 * @brief           The structure contains all needed flags and other items for
 *                  creating the head of DNS messages for communication
 *                  with the DNS server.
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
    uint8_t Z  :1;        ///< Reserver for the future use
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
 * @brief           The structure for definition the Question format used to
 *                  carry the "question" in most queries.
 */
struct QUESTION_FORMAT {
    uint16_t QTYPE;       ///< two octet code which specifies the type of the query
    uint16_t QCLASS;      ///< two octet code that specifies the class of the query
};


/* Constant sized fields of query structure */
/**
 * @brief           The structure for Resource record format. All sections
 *                  (answer, authority, additional) share the same format.
 */
struct __attribute__((__packed__)) RESOURCE_FORMAT {
    uint16_t TYPE;        ///< two octets containing one of the RR type codes
    uint16_t CLASS;       ///< two octets which specify the class of the data in the RDATA field
    uint32_t TTL;           ///< a 32 bit unsigned integer that specifies the time interval (in seconds)
    uint16_t RDLENGTH;    ///< 16 bit integer that specifies the length in octets of the RDATA field
};
