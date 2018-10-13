#include "InterfaceSniffer.h"

u_char* InterfaceSniffer::unknown_name_interface()
{
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct bpf_program fp;		/* The compiled filter expression */
    char filter_exp[] = "port 53";	/* The filter expression */
    bpf_u_int32 netaddr;            // network address configured at the input device
    bpf_u_int32 mask;               // network mask of the input device

    const char *name = "enp4s0f1";

    // get IP address and mask of the sniffing interface
    if (pcap_lookupnet(name, &netaddr, &mask, errbuf) == -1) {
        std::cerr << "pcap_lookupnet() failed" << endl;
        netaddr = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    pcap_t *handle = pcap_open_live(name, BUFSIZ, 1, this->time_in_seconds*1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", this->interface_name.c_str(), errbuf);
    }

    // compile the filter
    //if (pcap_compile(handle, &fp, filter_exp, 0, netaddr) == -1) {
    //    std::cerr << "pcap_compile() failed" << endl;
    //}

    // set the filter to the packet capture handle
    //if (pcap_setfilter(handle, &fp) == -1) {
    //    std::cerr << "pcap_setfilter() failed" << endl;
    //}

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
