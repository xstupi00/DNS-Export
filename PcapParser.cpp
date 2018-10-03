#include "PcapParser.h"
#include "DnsStructures.h"

void PcapParser::parse_pcap_file()
{
    char errbuff[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "port 53";
    bpf_u_int32 net;

    pcap_t *handle = pcap_open_offline("dns.pcap", errbuff);
    if (handle == nullptr) {
        std::cerr << "Couldn't open file:" << endl;
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }


    if (pcap_loop(handle, 0, my_pcap_handler, nullptr) < 0) {
        cout << "pcap_loop() failed: " << pcap_geterr(handle);
    }
}

void my_pcap_handler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    const struct ether_header* ethernetHeader;
    u_char *payload;

    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

        if (ipHeader->ip_p == IPPROTO_TCP) {
            //const struct tcphdr* tcpHeader = (tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
            payload = (u_char *) (packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            //const struct udphdr* udpHeader = (udphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
            payload = (u_char *) (packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
        }
    }

    const struct DNS_HEADER *dns_header = (struct DNS_HEADER *) payload;
    if (dns_header->QR == 1 && ntohs(dns_header->RCODE) == 0 && ntohs(dns_header->ANCOUNT) > 0) {
        std::cout << "Correct Answer" << endl;
    }
}