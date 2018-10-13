#include "FileSniffer.h"

const unsigned char* convert(const std::string& s){
    unsigned char* bytes=new unsigned char[s.size()+1]();
    std::copy(s.begin(),s.end(),bytes);
    return(bytes);
}

void FileSniffer::parse_pcap_file(const char *pcap_file_name)
{
    char errbuff[PCAP_ERRBUF_SIZE];	/* Error string */
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct bpf_program fp;		/* The compiled filter expression */
    char filter_exp[] = "port 53";	/* The filter expression */

    /* Open the session in promiscuous mode */
    pcap_t *handle = pcap_open_offline(pcap_file_name, errbuff);
    if (handle == nullptr) {
        std::cerr << "Couldn't open file:" << endl;
    }

    // compile the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1)
        std::cerr << "pcap_compile() failed" << endl;

    // set the filter to the packet capture handle
    if (pcap_setfilter(handle, &fp) == -1)
        std::cerr << "pcap_setfilter() failed" << endl;

    while((packet = pcap_next(handle, &header)) != nullptr) {
        u_char* payload = this->my_pcap_handler(packet, false);
        if (payload) {
            this->parse_payload(payload, false);
        }
    }
    this->proccess_tcp_packets();

    for ( auto it = this->stats.begin(); it != this->stats.end(); ++it )
        std::cout << it->first << " " << it->second << endl;
}
