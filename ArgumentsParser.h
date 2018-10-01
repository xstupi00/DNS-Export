#ifndef ARGUMENTSPARSER_H
#define ARGUMENTSPARSER_H

#include <getopt.h>
#include <cstring>
#include <cstdlib>
#include <stdio.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>
#include <arpa/inet.h> //
#include <sys/stat.h>
#include <iostream>
#include <netinet/in.h> //
#include <sys/socket.h> //
#include <netdb.h> //
#include <string>
#include <vector>
#include <sstream>
#include <sys/ioctl.h>
#include <net/if.h>


#include "DnsExport.h"

using namespace std;


class ArgumentParser: public DnsExport
{
    public:
        ArgumentParser();
        ~ArgumentParser();

        void parse_arguments(int argc, char**argv);

    private:
        void file_proccessing(const std::string& file_name);
        struct AddressWrapper syslog_address_proccessing(const std::string& addr);
        bool is_interface_online(std::string interface);
        void get_interface_addr(std::string interface);
        void get_IPv4_elements(std::vector<struct sockaddr_in> vector_IPv4);
        void get_IPv6_elements(std::vector<struct sockaddr_in6> vector_IPv6);
        bool duplicate_interface(std::string interface);
        bool duplicate_timeout(double time_in_seconds);
        void print_arguments();
};


#endif //ARGUMENTSPARSER_H
