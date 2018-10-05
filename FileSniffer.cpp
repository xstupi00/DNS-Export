#include "FileSniffer.h"

void FileSniffer::parse_pcap_file(const char *pcap_file_name)
{
    char errbuff[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "port 53";
    bpf_u_int32 net;
    const unsigned char *packet;
    struct pcap_pkthdr header;

    pcap_t *handle = pcap_open_offline(pcap_file_name, errbuff);
    if (handle == nullptr) {
        std::cerr << "Couldn't open file:" << endl;
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }


    while((packet = pcap_next(handle, &header)) != nullptr) {
        u_char* payload = this->my_pcap_handler(packet);
        this->parse_payload(payload);
    }
}