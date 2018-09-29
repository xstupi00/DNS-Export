#ifndef ARGUMENTSPARSER_H
#define ARGUMENTSPARSER_H

#include <getopt.h>
#include <cstring>
#include <cstdlib>
#include <stdio.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <pcap.h>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
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
        inline void file_proccessing(const std::string& file_name);
        inline void syslog_address_proccessing(const std::string& addr);
        inline bool is_interface_online(std::string interface);
        inline void get_interface_addr(std::string interface);
        void get_IPv4_elements(std::vector<struct sockaddr_in> vector_IPv4);
        void get_IPv6_elements(std::vector<struct sockaddr_in6> vector_IPv6);
};


#endif //ARGUMENTSPARSER_H
