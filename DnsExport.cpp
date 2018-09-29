#include <iostream>
#include <csignal>
#include <unistd.h>

#include "DnsExport.h"
#include "ArgumentsParser.h"


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
}