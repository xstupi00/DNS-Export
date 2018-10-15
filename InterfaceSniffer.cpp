#include <chrono>
#include <cmath>
#include <unistd.h>
#include "InterfaceSniffer.h"

u_char* InterfaceSniffer::sniffing_interface(std::string device_name, double time_in_seconds)
{
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct bpf_program fp;		/* The compiled filter expression */
    char filter_exp[] = "port 53";	/* The filter expression */
    bpf_u_int32 netaddr;            // network address configured at the input device
    bpf_u_int32 mask;               // network mask of the input device


    // get IP address and mask of the sniffing interface
    if (pcap_lookupnet(device_name.c_str(), &netaddr, &mask, errbuf) == -1) {
        std::cerr << "pcap_lookupnet() failed" << endl;
        netaddr = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    pcap_t *handle = pcap_open_live(device_name.c_str(), BUFSIZ, 1, -1, errbuf);
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

    time_t start, end;
    double diff = 0;
    time (&start);
    while(islessequal(diff, time_in_seconds)) {
        if ((packet = pcap_next(handle, &header)) != nullptr) {
            u_char *payload = this->my_pcap_handler(packet, false);
            if (payload) {
                this->parse_payload(payload, false);
            }
        }
        diff = difftime(time(&end), start);
    }
    diff = difftime(time(&end), start);
    std::cout << "END TIME = " << diff << endl;

    while(((packet = pcap_next(handle, &header)) != nullptr)) {
        std::cout << "REMAINING_PACKET" << endl;
        u_char *payload = this->my_pcap_handler(packet, false);
        if (payload) {
            this->parse_payload(payload, false);
        }
    }

    this->proccess_tcp_packets();

    for ( auto it = this->stats.begin(); it != this->stats.end(); ++it )
        std::cout << it->first << " " << it->second << endl;
}
