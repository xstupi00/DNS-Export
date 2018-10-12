#define DNS_ANS_TYPE_A     1
#define DNS_ANS_TYPE_NS     2
#define DNS_ANS_TYPE_CNAME 5
#define DNS_ANS_TYPE_SOA 6
#define DNS_ANS_TYPE_PTR 12
#define DNS_ANS_TYPE_MX 15
#define DNS_ANS_TYPE_AAAA 28
#define DNS_ANS_TYPE_DS 43
#define DNS_ANS_TYPE_RRSIG 46
#define DNS_ANS_TYPE_NSEC 47
#define DNS_ANS_TYPE_DNSKEY 48

#define NEXTHDR_HOP		    0	/* Hop-by-hop option header. */
#define NEXTHDR_IPV6		41	/* IPv6 in IPv6 */
#define NEXTHDR_ROUTING		43	/* Routing header. */
#define NEXTHDR_FRAGMENT	44	/* Fragmentation/reassembly header. */
#define NEXTHDR_GRE		    47	/* GRE header. */
#define NEXTHDR_ESP		    50	/* Encapsulating security payload. */
#define NEXTHDR_AUTH		51	/* Authentication header. */
#define NEXTHDR_ICMP		58	/* ICMPv6 message */
#define NEXTHDR_NONE		59	/* No next header */
#define NEXTHDR_DEST		60	/* Destination options header. */
#define NEXTHDR_SCTP		132	/* SCTP message. */
#define NEXTHDR_MOBILITY	135	/* Mobility header. */

#define IP_HEADER_MIN_LEN   20
#define IP_HEADER_MAX_LEN   60
#define PORT_DNS_NUMBER 53
#define IPv6_HEADER_LEN 40
#define EIGHT_OCTET_UNIT_TO_BYTES 3
#define FOUR_OCTET_UNIT_TO_BYTES 2

std::string decode_rr_type(int rr_type);



struct auth_hdr
{
    uint8_t  ip6h_nxt;		/* next header.  */
    uint8_t  ip6h_len;		/* length in units of 8 octets.  */
    uint16_t ip6h_res;      /* reserved 2 bytes */
    uint32_t ip6h_spi;      /* security parameters index */
    /* followed by 32-bits sequence number */
    /* followed by authentication data with variable length */
};

struct ipv6_hbh
{
    uint8_t  ip6h_nxt;		/* next header.  */
    uint8_t  ip6h_len;		/* length in units of 8 octets.  */
    uint16_t ip6h_opt;      /* options and padding */
    uint32_t ip6h_pad;      /* options and padding */
    /* can be followed by more options and padding */
};

struct ipv6_dest
{
    uint8_t  ip6d_nxt;		/* next header */
    uint8_t  ip6d_len;		/* length in units of 8 octets */
    uint16_t ip6h_opt;      /* options and padding */
    uint32_t ip6h_pad;      /* options and padding */
    /* can be followed by more options and padding */
};

struct ipv6_rthdr
{
    uint8_t  ip6r_nxt;		/* next header */
    uint8_t  ip6r_len;		/* length in units of 8 octets */
    uint8_t  ip6r_type;		/* routing type */
    uint8_t  ip6r_segleft;	/* segments left */
    uint32_t ip6r_data;     /* specific data */
    /* followed by routing type specific data */
};

struct ipv6_mobility
{
    uint8_t  ip6m_nxt;		/* next header */
    uint8_t  ip6m_len;		/* length in units of 8 octets */
    uint8_t  ip6m_type;		/* routing type */
    uint8_t  ip6m_reserve;  /* reserving space */
    uint16_t ip6m_checksum; /* checksum */
    uint16_t ip6m_data;     /* mandatory size of the data */
    /* can be followed by more data */
};

struct ns_preference
{
    unsigned short preference;
};

struct soa_record
{
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t min_ttl;
};

struct rrsig_record
{
    uint16_t  type_covered;
    uint8_t algorithm;
    uint8_t labels;
    uint32_t orig_ttl;
    uint32_t signature_exp;
    uint32_t signature_inc;
    uint16_t key_tag;
};

struct ds_record
{
    uint16_t key_id;
    uint8_t algorithm;
    uint8_t digest_type;
};

struct nsec_record
{
    uint16_t bit_maps_count;
};

struct dnskey_record
{
    uint16_t flags;
    uint8_t protocol;
    uint8_t algorithm;
};

/**
 * @brief           The structure contains all needed flags and other items for
 *                  creating the head of DNS messages for communication
 *                  with the DNS server.
 */
struct DNS_HEADER {
    unsigned short length; ///< tcp temporary

    unsigned short ID;          ///< 16 bit identifier assigned by the program

    unsigned char RD :1;        ///< Recursion Desired
    unsigned char TC :1;        ///< TrunCation
    unsigned char AA :1;        ///< Authorirative Answer
    unsigned char OPCODE :4;    ///< 4 bit field that species kind of query
    unsigned char QR :1;        ///< Query or Response message
    unsigned char RCODE  :4;    ///< 4 bit field is set as part of responses
    unsigned char CD :1;        ///< Checking Disabled
    unsigned char AD :1;        ///< Authenticated Data
    unsigned char Z  :1;        ///< Reserver for the future use
    unsigned char RA :1;        ///< Recursion Available

    unsigned short QDCOUNT;     ///< number of entries in the question section.
    unsigned short ANCOUNT;     ///< number of resource records in the answer section.
    unsigned short NSCOUNT;     ///< number of name server resource records in the authority records section.
    unsigned short ARCOUNT;     ///< number of resource records in the additional records section
};

/**
 * @brief           The structure for definition the Question format used to
 *                  carry the "question" in most queries.
 */
struct QUESTION_FORMAT {
    //unsigned char *NAME;        ///< domain name to which this resource record pertains
    unsigned short QTYPE;       ///< two octet code which specifies the type of the query
    unsigned short QCLASS;      ///< two octet code that specifies the class of the query
};


/* Constant sized fields of query structure */
//#pragma pack(push, 1)
/**
 * @brief           The structure for Resource record format. All sections
 *                  (answer, authority, additional) share the same format.
 */
struct RESOURCE_FORMAT {
    unsigned short TYPE;        ///< two octets containing one of the RR type codes
    unsigned short CLASS;       ///< two octets which specify the class of the data in the RDATA field
    unsigned int TTL;           ///< a 32 bit unsigned integer that specifies the time interval (in seconds)
    unsigned short RDLENGTH;    ///< 16 bit integer that specifies the length in octets of the RDATA field
};
//#pragma pack(pop)


/**
 * @brief           The structure for better abstraction resources records.
 *                  Contains individually pointers to contents of records.
 */
struct DATA_FORMAT {
    unsigned char *NAME;        ///< domain name to which this resource record pertains
    struct RESOURCE_FORMAT *RESOURCE; ///< pointer to structure contains needed to processing resource records
    unsigned char *RDATA;       ///< variable length string of octets that describes the resource
};
