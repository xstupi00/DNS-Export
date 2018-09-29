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


void ArgumentParser::get_IPv4_elements(std::vector<struct sockaddr_in> vector_IPv4)
{
    char addr_IPv4[INET_ADDRSTRLEN];
    std::cout << "IPv4 Addresses: " << endl;
    for(unsigned int i = 0; i < vector_IPv4.size(); i++) {
        inet_ntop(AF_INET, &(vector_IPv4.at(i).sin_addr), addr_IPv4, INET_ADDRSTRLEN);
        std::cout << "Element[" << i << "] = " << addr_IPv4 << std::endl;
    }
    std::cout << std::endl;
}


void ArgumentParser::get_IPv6_elements(std::vector<struct sockaddr_in6> vector_IPv6)
{
    char addr_IPv6[INET6_ADDRSTRLEN];
    std::cout << "IPv6 Addresses: " << endl;
    for(unsigned int i = 0; i < vector_IPv6.size(); i++) {
        inet_ntop(AF_INET6, &(vector_IPv6.at(i).sin6_addr), addr_IPv6, INET6_ADDRSTRLEN);
        std::cout << "Element[" << i << "] = " << addr_IPv6 << std::endl;
    }
    std::cout << std::endl;
}


inline void ArgumentParser::file_proccessing(const std::string& file_name)
{
    std::string delimiter = ".";
    std::string token = file_name.substr(file_name.find_first_of(delimiter), file_name.find(delimiter));
    struct stat buffer;
    if (stat (file_name.c_str(), &buffer) == 0 && token == ".pcap") {
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
        if (!he) {
            std::cerr << "Invalid address of syslog_server." << endl;
        } else {
            if (he->h_addrtype == AF_INET) {
                struct in_addr **addr_list = (struct in_addr **) he->h_addr_list;
                for (int i = 0; addr_list[i]; i++) {
                    struct sockaddr_in addr_IPv4;
                    addr_IPv4.sin_family = AF_INET;
                    memcpy(&addr_IPv4.sin_addr, addr_list[i], sizeof(&addr_list[i]));
                    this->syslog_server_addr.addr_IPv4.push_back(addr_IPv4);
                }
                //inet_pton(AF_INET, map_addr.c_str(), &this->syslog_server_addr.addr_IPv4.sin_addr);
            } else if (he->h_addrtype == AF_INET6) {
                struct in_addr6 **addr_list = (struct in_addr6 **) he->h_addr_list;
                for (int i = 0; addr_list[i]; i++) {
                    struct sockaddr_in6 addr_IPv6;
                    addr_IPv6.sin6_family = AF_INET6;
                    memcpy(&addr_IPv6.sin6_addr, addr_list[i], sizeof(&addr_list[i]));
                    this->syslog_server_addr.addr_IPv6.push_back(addr_IPv6);
                }
                //inet_pton(AF_INET6, map_addr.c_str(), &this->syslog_server_addr.addr_IPv6.sin6_addr);
            }
        }
    } else if (res->ai_family == AF_INET) {
        struct sockaddr_in addr_IPv4;
        addr_IPv4.sin_family = AF_INET;
        inet_pton(AF_INET, addr.c_str(), &addr_IPv4.sin_addr);
        this->syslog_server_addr.addr_IPv4.push_back(addr_IPv4);
    } else if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 addr_IPv6;
        addr_IPv6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, addr.c_str(), &addr_IPv6.sin6_addr);
        this->syslog_server_addr.addr_IPv6.push_back(addr_IPv6);
    }
}

bool ArgumentParser::is_interface_online(std::string interface)
{
    struct ifreq ifr;
    int sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP);
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, interface.c_str());
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror("SIOCGIFFLAGS");
    }
    close(sock);
    if (!!(ifr.ifr_flags & IFF_RUNNING)) {
        this->get_interface_addr(interface);
        return true;
    } else {
        return false;
    }
}


void ArgumentParser::get_interface_addr(std::string interface)
{
    struct ifaddrs *ifAddrStruct, *ifa;
    void *tmpAddrPtr;

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || std::string(ifa->ifa_name) != interface) {
            //this->get_IPv4_elements(this->interface_addr.addr_IPv4);
            //this->get_IPv6_elements(this->interface_addr.addr_IPv6);
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) { // check it is IP4
            // is a valid IP4 Address
            /*tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            printf("%s IP Address %s\n", ifa->ifa_name, addressBuffer);

            struct sockaddr_in addr_IPv4;
            inet_pton(AF_INET, addressBuffer, &addr_IPv4);*/

            struct sockaddr_in addr_IPv4;
            addr_IPv4.sin_family = AF_INET;
            memcpy(
                    &addr_IPv4.sin_addr,
                    &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
                    sizeof(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr)
                );
            this->interface_addr.addr_IPv4.push_back(addr_IPv4);
            //this->interface_addr.addr_IPv4.push_back((struct sockaddr_in*)ifa->ifa_addr);
            //this->get_IPv4_elements(this->interface_addr.addr_IPv4);
            //this->get_IPv6_elements(this->interface_addr.addr_IPv6);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) { // check it is IP6
            // is a valid IP6 Address
            /*tmpAddrPtr=&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            char addressBuffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
            printf("%s IP Address %s\n", ifa->ifa_name, addressBuffer);*/

            struct sockaddr_in6 addr_IPv6;
            addr_IPv6.sin6_family = AF_INET6;
            memcpy(
                    &addr_IPv6.sin6_addr,
                    &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr,
                    sizeof(((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr)
                );
            this->interface_addr.addr_IPv6.push_back(addr_IPv6);

            //this->interface_addr.addr_IPv6.push_back(((struct sockaddr_in6 *)ifa->ifa_addr));
            //this->get_IPv4_elements(this->interface_addr.addr_IPv4);
            //this->get_IPv6_elements(this->interface_addr.addr_IPv6);
            /*char addressBuffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr_IPv6, addressBuffer, INET6_ADDRSTRLEN);
            printf("%s IP Address %s\n", ifa->ifa_name, addressBuffer);*/
        }
    }
    freeifaddrs(ifAddrStruct);
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
                this->is_interface_online(std::string(optarg));
                char addr4[INET_ADDRSTRLEN];
                //inet_ntop(AF_INET, &(this->syslog_server_addr.addr_IPv4.sin_addr), addr4, INET_ADDRSTRLEN);
                char addr6[INET6_ADDRSTRLEN];
                //inet_ntop(AF_INET6, &(this->syslog_server_addr.addr_IPv6.sin6_addr), addr6, INET6_ADDRSTRLEN);
                this->get_IPv4_elements(this->interface_addr.addr_IPv4);
                this->get_IPv6_elements(this->interface_addr.addr_IPv6);
                //std::cout << "syslog_server IPV4: " << addr4 << std::endl;
                //std::cout << "syslog_server IPV6: " << addr6 << std::endl;
                break;
            case 's':
                this->syslog_address_proccessing(optarg);
                char addr[INET_ADDRSTRLEN];
                //inet_ntop(AF_INET, &(this->syslog_server_addr.addr_IPv4.sin_addr), addr, INET_ADDRSTRLEN);
                this->get_IPv4_elements(this->syslog_server_addr.addr_IPv4);
                this->get_IPv6_elements(this->syslog_server_addr.addr_IPv6);
                //std::cout << "syslog_server: " << addr << std::endl;
                break;
            case 't':
                this->time_in_second = strtol(optarg, nullptr, 10);
                std::cout << "seconds: " << this->time_in_second << std::endl;
                break;
            default:
                cout << "Argument error!" << endl;
                exit(-1);
        }
    }
}