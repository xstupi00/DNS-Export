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

    /* Open the session in promiscuous mode */
    pcap_t *handle = pcap_open_offline(pcap_file_name, errbuff);
    if (handle == nullptr) {
        std::cerr << "Couldn't open file:" << endl;
    }

    while((packet = pcap_next(handle, &header)) != nullptr) {
        u_char* payload = this->my_pcap_handler(packet, false);
        if (payload) {
            this->parse_payload(payload);
        }
    }

    this->proccess_tcp_packets();
}