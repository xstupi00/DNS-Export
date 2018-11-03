#include <bitset>
#include "ArgumentsParser.h"


/**
* Default Contructor.
*/
ArgumentParser::ArgumentParser() = default;

/**
* Destructor.
*/
ArgumentParser::~ArgumentParser() = default;


void ArgumentParser::proccess_file_argument(const std::string &file_name) {
    struct stat sb = {};
    if (stat(file_name.c_str(), &sb) == 0) {
        this->pcap_files.emplace_back(std::string(file_name));
    } else {
        std::perror("stat() failed: ");
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
            std::perror("gethostbyname() failed: ");
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
                auto addr_list = (struct in_addr6 **) he->h_addr_list;
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
                std::cerr << "inet_pton() failed: Not in presentation format" << std::endl;
            } else {
                std::perror("inet_pton() failed:");
            }
        }
        address_wrapper.addr_IPv4.push_back(addr_IPv4);
        freeaddrinfo(res);  /* No longer needed */
    } else if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 addr_IPv6 = {};
        addr_IPv6.sin6_family = AF_INET6;

        s = inet_pton(AF_INET6, addr.c_str(), &addr_IPv6.sin6_addr);
        if (s <= 0) {
            if (!s) {
                std::cerr << "inet_pton() failed: Not in presentation format" << std::endl;
            } else {
                std::perror("inet_pton() failed:");
            }
        }
        address_wrapper.addr_IPv6.push_back(addr_IPv6);
        freeaddrinfo(res);  /* No longer needed */
    } else {
        std::cerr << "getaddrinfo() failed: " << gai_strerror(s) << std::endl;
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
            {nullptr,         0,                 nullptr,  0 },
    };

    std::bitset<4> args_arr;

    int opt;
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'h': {
                std::cout << "PRINT USAGE PLEASE!" << std::endl;
                exit(args_arr.any() ? EXIT_FAILURE : EXIT_SUCCESS);
            }
            case 'r': {
                if (args_arr.to_ulong() & 0b0101) {
                    std::cerr << "Wrong combinations of arguments!" << std::endl;
                    exit(EXIT_FAILURE);
                } else {
                    this->proccess_file_argument(optarg);
                }
                args_arr.set(0);
                break;
            }
            case 'i': {
                if (args_arr.test(0)) {
                    std::cerr << "Wrong combinations of arguments!" << std::endl;
                    exit(EXIT_FAILURE);
                } else {
                    args_arr.set(1);
                    this->interface_name = std::string(optarg);
                }
                break;
            }
            case 's': {
                args_arr.set(2);
                struct AddressWrapper syslog_server;
                syslog_server = this->proccess_syslog_address(optarg);
                this->syslog_server_addr.push_back(syslog_server);
                break;
            }
            case 't': {
                if (args_arr.test(0)) {
                    std::cerr << "Wrong combinations of arguments!" << std::endl;
                    exit(EXIT_FAILURE);
                } else {
                    args_arr.set(3);
                    this->time_in_seconds = (unsigned) std::stoi(optarg);
                }
                break;
            }
            default: {
                std::cerr << "Wrong combinations of arguments!" << std::endl;
                exit(EXIT_FAILURE);
            }
        }

        if (!(args_arr.to_ulong() & 0b0011)) {
            std::cerr << "Wrong combinations of arguments!" << std::endl;
            exit(EXIT_FAILURE);
        }
    }
}