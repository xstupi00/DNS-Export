#ifndef ARGUMENTSPARSER_H
#define ARGUMENTSPARSER_H

#include <arpa/inet.h>
#include <cstring>
#include <getopt.h>
#include <ifaddrs.h>
#include <iostream>
#include <netdb.h>
#include <net/if.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "DnsExport.h"

using namespace std;


class ArgumentParser: public DnsExport
{
    public:
        ArgumentParser();
        ~ArgumentParser();

        void parse_arguments(int argc, char**argv);
        void print_arguments();

private:
        bool proccess_duplicate_interface(std::string interface);
        bool proccess_duplicate_timeout(double time_in_seconds);
        void proccess_file_argument(const std::string& file_name);
        void get_interface_addr(std::string interface);
        void get_IPv4_elements(std::vector<struct sockaddr_in> vector_IPv4);
        void get_IPv6_elements(std::vector<struct sockaddr_in6> vector_IPv6);
        bool is_interface_online(std::string interface);
        struct AddressWrapper proccess_syslog_address(const std::string& addr);
};


#endif //ARGUMENTSPARSER_H
