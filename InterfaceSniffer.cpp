#include "InterfaceSniffer.h"

u_char* InterfaceSniffer::unknown_name_interface()
{
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    const unsigned char *packet;
    struct pcap_pkthdr header;

    const char *name = "enp4s0f1";

    /* Open the session in promiscuous mode */
    pcap_t *handle = pcap_open_live(name, BUFSIZ, 1, this->time_in_seconds*1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", this->interface_name.c_str(), errbuf);
    }

    while((packet = pcap_next(handle, &header)) != nullptr) {
        u_char* payload = this->my_pcap_handler(packet, false);
        if (payload) {
            this->parse_payload(payload);
        }
    }
}
