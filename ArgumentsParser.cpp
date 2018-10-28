#include "ArgumentsParser.h"


/**
* Default Contructor.
*/
ArgumentParser::ArgumentParser() = default;

/**
* Destructor.
*/
ArgumentParser::~ArgumentParser() = default;


///< debug functions for printing vector contains the IPv4 addresses
void ArgumentParser::get_IPv4_elements(std::vector<struct sockaddr_in> vector_IPv4) {
    char addr_IPv4[INET_ADDRSTRLEN];
    std::cout << "IPv4 Addresses: " << std::endl;
    for (unsigned int i = 0; i < vector_IPv4.size(); i++) {
        if (inet_ntop(AF_INET, &(vector_IPv4.at(i).sin_addr), addr_IPv4, INET_ADDRSTRLEN) == nullptr)
            perror("inet_ntop");
        std::cout << "Address[" << i << "] = " << addr_IPv4 << std::endl;
    }
    std::cout << std::endl;
}

///< debug functions for printing vector contains the IPv6 addresses
void ArgumentParser::get_IPv6_elements(std::vector<struct sockaddr_in6> vector_IPv6) {
    char addr_IPv6[INET6_ADDRSTRLEN];
    std::cout << "IPv6 Addresses: " << std::endl;
    for (unsigned int i = 0; i < vector_IPv6.size(); i++) {
        if (inet_ntop(AF_INET6, &(vector_IPv6.at(i).sin6_addr), addr_IPv6, INET6_ADDRSTRLEN) == nullptr)
            perror("inet_ntop");
        std::cout << "Address[" << i << "] = " << addr_IPv6 << std::endl;
    }
    std::cout << std::endl;
}

void ArgumentParser::print_arguments() {
    std::cout << "seconds: " << this->time_in_seconds << std::endl;
    std::cout << "---------------------------------" << std::endl;

    for (unsigned int i = 0; i < this->syslog_server_addr.size(); i++) {
        std::cout << "Syslog server no. " << i << ":" << std::endl;
        this->get_IPv4_elements(this->syslog_server_addr.at(i).addr_IPv4);
        this->get_IPv6_elements(this->syslog_server_addr.at(i).addr_IPv6);
    }
    std::cout << "---------------------------------" << std::endl;

    std::cout << "Interface name: " << std::endl;
    std::cout << "---------------------------------" << std::endl;

    std::cout << "Pcap files: " << std::endl;
    for (unsigned int i = 0; i < this->pcap_files.size(); i++) {
        std::cout << "pcap_file no. " << i << ": " << this->pcap_files.at(i) << std::endl;
    }
}


void ArgumentParser::proccess_file_argument(const std::string &file_name) {
    struct stat sb = {};
    if (stat(file_name.c_str(), &sb) == 0) {
        this->pcap_files.emplace_back(std::string(file_name));
    } else {
        std::cerr << "Invalid pcap file: " << file_name << std::endl;
    }
}

struct AddressWrapper ArgumentParser::proccess_syslog_address(const std::string &addr) {
    struct addrinfo *res, hint = {};
    struct AddressWrapper address_wrapper = {};

    memset(&hint, '\0', sizeof(hint));
    hint.ai_family = PF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hint.ai_flags = AI_NUMERICHOST;

    int s = getaddrinfo(addr.c_str(), nullptr, &hint, &res);
    if (not res and s) {
        struct hostent *he = gethostbyname(addr.c_str());
        if (!he) {
            std::cerr << "Invalid address/hostname of syslog_server: " << addr << std::endl;
        } else {
            if (he->h_addrtype == AF_INET) {
                auto addr_list = (struct in_addr **) he->h_addr_list;
                for (int i = 0; addr_list[i]; i++) {
                    struct sockaddr_in addr_IPv4 = {};
                    addr_IPv4.sin_family = AF_INET;
                    memcpy(&addr_IPv4.sin_addr, addr_list[i], sizeof(&addr_list[i]));
                    address_wrapper.addr_IPv4.push_back(addr_IPv4);
                }
            } else if (he->h_addrtype == AF_INET6) {
                struct in_addr6 **addr_list = (struct in_addr6 **) he->h_addr_list;
                for (int i = 0; addr_list[i]; i++) {
                    struct sockaddr_in6 addr_IPv6 = {};
                    addr_IPv6.sin6_family = AF_INET6;
                    memcpy(&addr_IPv6.sin6_addr, addr_list[i], sizeof(&addr_list[i]));
                    address_wrapper.addr_IPv6.push_back(addr_IPv6);
                }
            }
        }
    } else if (res->ai_family == AF_INET) {
        struct sockaddr_in addr_IPv4 = {};
        addr_IPv4.sin_family = AF_INET;

        s = inet_pton(AF_INET, addr.c_str(), &addr_IPv4.sin_addr);
        if (s <= 0) {
            if (!s) {
                std::cerr << "Not in presentation format" << std::endl;
            } else {
                perror("inet_pton");
            }
        }
        address_wrapper.addr_IPv4.push_back(addr_IPv4);
        freeaddrinfo(res);  /* No longer needed */
    } else if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 addr_IPv6 = {};
        addr_IPv6.sin6_family = AF_INET6;

        s = inet_pton(AF_INET6, addr.c_str(), &addr_IPv6.sin6_addr);
        if (s <= 0) {
            if (!s)
                std::cerr << "IPv6 address in not in presentation format" << std::endl;
            else
                std::cerr << "inet_pton: " << gai_strerror(s) << std::endl;
        }
        address_wrapper.addr_IPv6.push_back(addr_IPv6);
        freeaddrinfo(res);  /* No longer needed */
    } else {
        std::cerr << "getaddrinfo: " << gai_strerror(s) << std::endl;
    }
    return address_wrapper;
}


void ArgumentParser::parse_arguments(int argc, char **argv) {
    const char *const short_opts = "hr:i:s:t:";
    const option long_opts[] = {
            {"pcap_file",     required_argument, nullptr, 'r'},
            {"interface",     required_argument, nullptr, 'i'},
            {"syslog_server", required_argument, nullptr, 's'},
            {"seconds",       required_argument, nullptr, 't'},
            {"help",          no_argument,       nullptr, 'h'},
            {nullptr, 0,                         nullptr, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'h': {
                std::cout << "PRINT HELP PLEASE!" << std::endl; // TODO: USAGE/HELP
                break;
            }
            case 'r': {
                this->proccess_file_argument(optarg);
                break;
            }
            case 'i': {
                this->interface_name = std::string(optarg); // TODO: any interface
                break;
            }
            case 's': {
                struct AddressWrapper syslog_server;
                syslog_server = this->proccess_syslog_address(optarg);
                this->syslog_server_addr.push_back(syslog_server);
                break;
            }
            case 't': {
                this->time_in_seconds = std::stoi(optarg);
                break;
            }
            default: {
                std::cerr << "Argument error!" << std::endl;
                exit(-1);
            }
        }
    }
}