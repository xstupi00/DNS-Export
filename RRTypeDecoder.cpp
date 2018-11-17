#include <string>
#include <pcap-bpf.h>


std::string decode_rr_type(int rr_type) {
    if (rr_type >= 65280 and rr_type <= 65534) rr_type = 65280;

    switch (rr_type) {
        case 1: return "A";
        case 2: return "NS";
        case 3: return "MD";
        case 4: return "MF";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 7: return "MB";
        case 8: return "MG";
        case 9: return "MR";
        case 10: return "NULL";
        case 11: return "WKS";
        case 12: return "PTR";
        case 13: return "HINFO";
        case 14: return "MINFO";
        case 15: return "MX";
        case 16: return "TXT";
        case 17: return "RP";
        case 18: return "AFSDB";
        case 19: return "X25";
        case 20: return "ISDN";
        case 21: return "RT";
        case 22: return "NSAP";
        case 23: return "NSAP_PTR";
        case 24: return "SIG";
        case 25: return "KEY";
        case 26: return "PX";
        case 27: return "GPOS";
        case 28: return "AAAA";
        case 29: return "LOC";
        case 30: return "NXT";
        case 31: return "EID";
        case 32: return "NIMLOC";
        case 33: return "SRV";
        case 34: return "ATMA";
        case 35: return "NAPTR";
        case 36: return "KX";
        case 37: return "CERT";
        case 38: return "A6";
        case 39: return "DNAME";
        case 40: return "SINK";
        case 41: return "OPT";
        case 42: return "APL";
        case 43: return "DS";
        case 44: return "SSHFP";
        case 45: return "IPSECKEY";
        case 46: return "RRSIG";
        case 47: return "NSEC";
        case 48: return "DNSKEY";
        case 49: return "DHCID";
        case 50: return "NSEC3";
        case 51: return "NSEC3PARAM";
        case 52: return "TLSA";
        case 53: return "SMIMEA";
        case 55: return "HIP";
        case 56: return "NINFO";
        case 57: return "RKEY";
        case 58: return "TALINK";
        case 59: return "CDS";
        case 60: return "CDNSKEY";
        case 61: return "OPENPGPKEY";
        case 62: return "CSYNC";
        case 99: return "SPF";
        case 100: return "UINFO";
        case 101: return "UID";
        case 102: return "GID";
        case 103: return "UNSPEC";
        case 104: return "NID";
        case 105: return "L32";
        case 106: return "L64";
        case 107: return "LP";
        case 108: return "EUI48";
        case 109: return "EUI64";
        case 249: return "TKEY";
        case 250: return "TSIG";
        case 251: return "IXFR";
        case 252: return "AXFR";
        case 253: return "MAILB";
        case 254: return "MAILA";
        case 255: return "ANY";
        case 256: return "URI";
        case 257: return "CAA";
        case 258: return "AVC";
        case 259: return "DOA";
        case 32768: return "TA";
        case 32769: return "DLV";
        case 65280: return "PRIVATE";
        case 65535: return "RESERVED";
        default: return "TYPE"+rr_type;
    }
}

std::string decode_algorithm(int algorithm) {
    if (algorithm >= 17 and algorithm <= 122) algorithm = 17;
    if (algorithm >= 123 and algorithm <= 251) algorithm = 123;

    switch (algorithm) {
        case 0: return "DELETE";
        case 1: return "RSAMD5";
        case 2: return "DH";
        case 3: return "DSASHA1";
        case 4: return "RESERVED";
        case 5: return "RSASHA1";
        case 6: return "DSANSEC3SHA1";
        case 7: return "RSASHA1NSEC3SHA1";
        case 8: return "RSA/SHA256";
        case 9: return "RESERVED";
        case 10: return "RSASHA512";
        case 11: return "RESERVED";
        case 12: return "ECCGOST";
        case 13: return "ECDSAP256SHA256";
        case 14: return "ECDSAP384SHA384";
        case 15: return "ED25519";
        case 16: return "ED448";
        case 17: return "UNASSIGNED";
        case 123: return "RESERVED";
        case 252: return "INDIRECT";
        case 253: return "PRIVATEDNS";
        case 254: return "PRIVATEOID";
        case 255: return "RESERVED";
        default: return "ALGORITHM"+algorithm;
    }
}

size_t get_length_of_datalink(int datalink_id) {
    switch (datalink_id) {
        case DLT_EN10MB:
            return 14;
        case DLT_IEEE802:
            return 22;
#ifdef __amigaos__
        case DLT_MIAMI:
            return 16;
#endif
#ifdef DLT_LOOP
        case DLT_LOOP:
#endif
        case DLT_NULL:
            return 4;
        case DLT_SLIP:
#ifdef DLT_SLIP_BSDOS
        case DLT_SLIP_BSDOS:
#endif
#if (FREEBSD || OPENBSD || NETBSD || BSDI || MACOSX)
            return 16;
#else
            return 24; /* Anyone use this??? */
#endif
        case DLT_PPP:
#ifdef DLT_PPP_BSDOS
        case DLT_PPP_BSDOS:
#endif
#ifdef DLT_PPP_SERIAL
        case DLT_PPP_SERIAL:
#endif
#ifdef DLT_PPP_ETHER
        case DLT_PPP_ETHER:
#endif
#if (FREEBSD || OPENBSD || NETBSD || BSDI || MACOSX)
            return 4;
#else
#ifdef SOLARIS
            return 8;
#else
            return 24; /* Anyone use this? */
#endif /* ifdef solaris */
#endif /* if freebsd || openbsd || netbsd || bsdi */
        case DLT_RAW:
            return 0;
        case DLT_FDDI:
            return 21;
#ifdef DLT_ENC
        case DLT_ENC:
            return 12;
#endif /* DLT_ENC */
#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
            return 16;
#endif
#ifdef DLT_IPNET
        case DLT_IPNET:
            return 24;
#endif
        default:
            return -1;
    }
}