#include "DnsExport.h"
#include "ArgumentsParser.h"
#include "PcapParser.h"
#include "InterfaceParser.h"


/**
* Default Contructor.
*/
DnsExport::DnsExport() = default;


/**
* Destructor.
*/
DnsExport::~DnsExport() = default;


void DnsExport::run(int argc, char **argv)
{
    ArgumentParser argument_parser;
    argument_parser.parse_arguments(argc, argv);

    //PcapParser pcap_parser;
    //pcap_parser.parse_pcap_file();

    InterfaceParser interface_parser;
    interface_parser.unknown_name_interface();
}