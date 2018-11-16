#ifndef ARGUMENTSPARSER_H
#define ARGUMENTSPARSER_H

#include <bitset>
#include <getopt.h>
#include <iostream>
#include <sys/stat.h>
#include <vector>

#include "DataStructures.h"

extern unsigned time_in_seconds;
extern std::vector<std::string> syslog_servers;

class ArgumentParser {
public:
    ArgumentParser();

    ~ArgumentParser();

    std::vector<std::string> pcap_files;
    std::string interface_name = "any";

    void parse_arguments(int argc, char **argv);
};

#endif //ARGUMENTSPARSER_H