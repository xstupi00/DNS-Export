#include "InterfaceSniffer.h"

u_char* InterfaceSniffer::unknown_name_interface()
{
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		    /* The compiled filter */
    char filter_exp[] = "port 53";	/* The filter expression */
    bpf_u_int32 mask;		        /* Our netmask */
    bpf_u_int32 net;		        /* Our IP */
    const unsigned char *packet;
    struct pcap_pkthdr header;


    /* Define the device */
    const char *dev = "enp4s0f1";

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    pcap_t *handler = pcap_open_live(dev, BUFSIZ, 1, this->time_in_seconds*5000, errbuf);
    if (handler == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handler, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handler));
    }
    if (pcap_setfilter(handler, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handler));
    }

    while((packet = pcap_next(handler, &header)) != nullptr) {
        u_char* payload = this->my_pcap_handler(packet);
        this->parse_payload(payload);
    }
}
