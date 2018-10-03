/**
 * @brief           The structure contains all needed flags and other items for
 *                  creating the head of DNS messages for communication
 *                  with the DNS server.
 */
struct DNS_HEADER {

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


/* Constant sized fields of query structure */
#pragma pack(push, 1)
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
#pragma pack(pop)


/**
 * @brief           The structure for better abstraction resources records.
 *                  Contains individually pointers to contents of records.
 */
struct DATA_FORMAT {
    unsigned char *NAME;        ///< domain name to which this resource record pertains
    struct RESOURCE_FORMAT *RESOURCE; ///< pointer to structure contains needed to processing resource records
    unsigned char *RDATA;       ///< variable length string of octets that describes the resource
};
