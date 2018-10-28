#ifndef ARGUMENTSPARSER_H
#define ARGUMENTSPARSER_H

#include <arpa/inet.h>
#include <string>
#include <getopt.h>
#include <netdb.h>
#include <sys/stat.h>
#include <vector>

#include "DataStructures.h"

class ArgumentParser {
public:
    ArgumentParser();

    ~ArgumentParser();

    std::vector<std::string> pcap_files;
    std::vector<struct AddressWrapper> syslog_server_addr;
    std::string interface_name = "";
    unsigned int time_in_seconds = 60;

    void parse_arguments(int argc, char **argv);

    void print_arguments();

private:
    void proccess_file_argument(const std::string &file_name);

    void get_IPv4_elements(std::vector<struct sockaddr_in> vector_IPv4);

    void get_IPv6_elements(std::vector<struct sockaddr_in6> vector_IPv6);

    struct AddressWrapper proccess_syslog_address(const std::string &addr);

    bool is_interface_online();
};


#endif //ARGUMENTSPARSER_H
