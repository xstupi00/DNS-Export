#include <getopt.h>
#include <cstring>
#include <cstdlib>
#include <sys/stat.h>
#include <pcap.h>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#include "ArgumentsParser.h"

using namespace std;

/**
* Default Contructor.
*/
ArgumentParser::ArgumentParser() = default;


/**
* Destructor.
*/
ArgumentParser::~ArgumentParser() = default;

inline void ArgumentParser::file_proccessing(const std::string& name)
{
    std::string delimiter = ".";
    std::string token = name.substr(name.find_first_of(delimiter), name.find(delimiter));
    struct stat buffer;
    if (stat (name.c_str(), &buffer) == 0 && token == ".pcap") {
        this->pcap_file = std::string(optarg);
    } else {
        std::cerr << "Invalid pcap file." << endl;
    }
}

inline void ArgumentParser::syslog_address_proccessing(const std::string& addr)
{
    struct addrinfo hint, *res;
    memset(&hint, '\0', sizeof hint);

    hint.ai_family = PF_UNSPEC;
    hint.ai_flags = AI_NUMERICHOST;

    getaddrinfo(addr.c_str(), nullptr, &hint, &res);
    if (!res){
        struct hostent *he = gethostbyname(addr.c_str());
        struct in_addr **addr_list;
        if (!he) {
            std::cerr << "Invalid address of syslog_server." << endl;
        } else {
            std::string map_addr = "::FFFF:";
            addr_list = (struct in_addr **) he->h_addr_list;
            for (int i = 0; addr_list[i]; i++) {
                map_addr += inet_ntoa(*addr_list[i]);
            }
            inet_pton(AF_INET6, map_addr.c_str(), &this->syslog_server_addr.sin6_addr);
        }
    } else if (res->ai_family == AF_INET) {
        std::string map_addr = "::FFFF:" + addr;
        inet_pton(AF_INET6, map_addr.c_str(), &this->syslog_server_addr.sin6_addr);
    } else if (res->ai_family == AF_INET6) {
        inet_pton(AF_INET6, addr.c_str(), &this->syslog_server_addr.sin6_addr);
    }
}

void ArgumentParser::parse_arguments(int argc, char **argv)
{
    const char* const short_opts = "hr:i:s:t:";
    const option long_opts[] = {
            {"pcap_file", required_argument, nullptr, 'r'},
            {"interface", required_argument, nullptr, 'i'},
            {"syslog_server", required_argument, nullptr, 's'},
            {"seconds", required_argument, nullptr, 't'},
            {"help", no_argument, nullptr, 'h'},
            {nullptr, 0, nullptr, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'h':
                std::cout << "PRINT HELP PLEASE!" << std::endl;
                break;
            case 'r':
                this->file_proccessing(optarg);
                std::cout << "pcap_file: " << this->pcap_file << std::endl;
                break;
            case 'i':
                std::cout << "interface: " << std::string(optarg) << std::endl;
                break;
            case 's':
                this->syslog_address_proccessing(optarg);
                char addr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &(this->syslog_server_addr.sin6_addr), addr, INET6_ADDRSTRLEN);
                std::cout << "syslog_server: " << addr << std::endl;
                break;
            case 't':
                this->time_in_second = atoi(optarg);
                std::cout << "seconds: " << this->time_in_second << std::endl;
                break;
            default:
                cout << "Argument error!" << endl;
                exit(-1);
        }
    }
}