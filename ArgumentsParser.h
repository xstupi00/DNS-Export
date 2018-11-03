#ifndef ARGUMENTSPARSER_H
#define ARGUMENTSPARSER_H

#include <arpa/inet.h>
#include <string>
#include <getopt.h>
#include <netdb.h>
#include <sys/stat.h>
#include <vector>
#include <cstring>
#include <iostream>
#include <net/if.h>

#include "DataStructures.h"

class ArgumentParser {
public:
    ArgumentParser();

    ~ArgumentParser();

    std::vector<std::string> pcap_files;
    std::vector<struct AddressWrapper> syslog_server_addr;
    std::string interface_name = "any";
    unsigned time_in_seconds = 60;

    void parse_arguments(int argc, char **argv);

private:
    void proccess_file_argument(const std::string &file_name);

    struct AddressWrapper proccess_syslog_address(const std::string &addr);
};

#endif //ARGUMENTSPARSER_H