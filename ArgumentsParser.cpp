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
        if (inet_ntop(AF_INET, &(vector_IPv4.at(i).sin_addr), addr_IPv4, INET_ADDRSTRLEN) == nullptr)
            perror("inet_ntop");
        std::cout << "Address[" << i << "] = " << addr_IPv4 << std::endl;
    }
    std::cout << std::endl;
}


void ArgumentParser::get_IPv6_elements(std::vector<struct sockaddr_in6> vector_IPv6)
{
    char addr_IPv6[INET6_ADDRSTRLEN];
    std::cout << "IPv6 Addresses: " << endl;
    for(unsigned int i = 0; i < vector_IPv6.size(); i++) {
        if (inet_ntop(AF_INET6, &(vector_IPv6.at(i).sin6_addr), addr_IPv6, INET6_ADDRSTRLEN) == nullptr)
            perror("inet_ntop");
        std::cout << "Address[" << i << "] = " << addr_IPv6 << std::endl;
    }
    std::cout << std::endl;
}


void ArgumentParser::file_proccessing(const std::string& file_name)
{
    std::string delimiter = ".";
    std::string token = file_name.substr(file_name.find_first_of(delimiter), file_name.find(delimiter));
    struct stat buffer;
    if (stat (file_name.c_str(), &buffer) == 0 && token == ".pcap") {
        this->pcap_files.emplace_back(std::string(optarg));
    } else {
        std::cerr << "Invalid pcap file: " << file_name << endl;
    }
}

struct AddressWrapper ArgumentParser::syslog_address_proccessing(const std::string& addr)
{
    struct addrinfo hint, *res;
    memset(&hint, '\0', sizeof hint);

    hint.ai_family = PF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hint.ai_flags = AI_NUMERICHOST;

    struct AddressWrapper address_wrapper;

    int s;
    getaddrinfo(addr.c_str(), nullptr, &hint, &res);
    /* if (!s) {
        std::cerr << "getaddrinfo: " <<  gai_strerror(s) << endl;
        // exit(EXIT_FAILURE);
    } */

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
                    address_wrapper.addr_IPv4.push_back(addr_IPv4);
                }
            } else if (he->h_addrtype == AF_INET6) {
                struct in_addr6 **addr_list = (struct in_addr6 **) he->h_addr_list;
                for (int i = 0; addr_list[i]; i++) {
                    struct sockaddr_in6 addr_IPv6;
                    addr_IPv6.sin6_family = AF_INET6;
                    memcpy(&addr_IPv6.sin6_addr, addr_list[i], sizeof(&addr_list[i]));
                    address_wrapper.addr_IPv6.push_back(addr_IPv6);
                }
            }
        }
    } else if (res->ai_family == AF_INET) {
        struct sockaddr_in addr_IPv4;
        addr_IPv4.sin_family = AF_INET;

        s = inet_pton(AF_INET, addr.c_str(), &addr_IPv4.sin_addr);
        if (s <= 0) {
            if (!s)
                std::cerr << "Not in presentation format" << endl;
            else
                perror("inet_pton");
            // exit(EXIT_FAILURE);
        }

        address_wrapper.addr_IPv4.push_back(addr_IPv4);
    } else if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 addr_IPv6;
        addr_IPv6.sin6_family = AF_INET6;

        s = inet_pton(AF_INET6, addr.c_str(), &addr_IPv6.sin6_addr);
        if (s <= 0) {
            if (!s)
                std::cerr << "Not in presentation format" << endl;
            else
                perror("inet_pton");
            // exit(EXIT_FAILURE);
        }

        address_wrapper.addr_IPv6.push_back(addr_IPv6);
    }
    freeaddrinfo(res);           /* No longer needed */

    return address_wrapper;
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
    // close(sock);
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

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || std::string(ifa->ifa_name) != interface) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) { // check it is IP4
            struct sockaddr_in addr_IPv4;
            addr_IPv4.sin_family = AF_INET;
            memcpy(
                    &addr_IPv4.sin_addr,
                    &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
                    sizeof(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr)
                );
            this->interface_addr.addr_IPv4.push_back(addr_IPv4);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) { // check it is IP6
            struct sockaddr_in6 addr_IPv6;
            addr_IPv6.sin6_family = AF_INET6;
            memcpy(
                    &addr_IPv6.sin6_addr,
                    &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr,
                    sizeof(((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr)
                );
            this->interface_addr.addr_IPv6.push_back(addr_IPv6);
        }
        this->interface_name = interface;
    }
    freeifaddrs(ifAddrStruct);
}

bool ArgumentParser::duplicate_interface(std::string interface)
{
    if (this->interface_name == interface)
        return false;
    std::cout << "You given another --interface (-i) argument:" << endl;
    std::cout << "Your actual interface for listening of DNS traffic is: " << this->interface_name << endl;
    std::cout << "Do you want replace actual interface " << this->interface_name <<\
    " by new interface: " << interface << "?" << endl;
    std::cout << "Please type 'yes' or 'no': ";
    std::string user_answer;
    std::cin >> user_answer;
    if (user_answer == "yes") {
        this->interface_addr.addr_IPv4.clear();
        this->interface_addr.addr_IPv6.clear();
        return true;
    }
    return false;
}

bool ArgumentParser::duplicate_timeout(double time_in_seconds)
{
    std::cout << "Do you want replace actual value of TIMEOUT " << this->time_in_seconds <<\
    " by new value: " << time_in_seconds << "?" << endl;
    std::cout << "Please type 'yes' or 'no': ";
    std::string user_answer;
    std::cin >> user_answer;
    if (user_answer == "yes") {
        return true;
    }
    return false;
}

void ArgumentParser::print_arguments()
{
    std::cout << "seconds: " << this->time_in_seconds << std::endl;
    std::cout << "---------------------------------" << std::endl;

    for (unsigned int i = 0; i < this->syslog_server_addr.size(); i++) {
        std::cout << "Syslog server no. " << i << ":" << endl;
        this->get_IPv4_elements(this->syslog_server_addr.at(i).addr_IPv4);
        this->get_IPv6_elements(this->syslog_server_addr.at(i).addr_IPv6);
    }
    std::cout << "---------------------------------" << std::endl;

    std::cout << "Interface: " << endl;
    this->get_IPv4_elements(this->interface_addr.addr_IPv4);
    this->get_IPv6_elements(this->interface_addr.addr_IPv6);
    std::cout << "---------------------------------" << std::endl;

    std::cout << "Pcap files: " << endl;
    for(unsigned int i = 0; i < this->pcap_files.size(); i++) {
        std::cout << "pcap_file no. " << i << ": " << this->pcap_files.at(i) << endl;
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
    bool duplicity_timeout = false;
    bool duplicity_interface = false;
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'h': {
                std::cout << "PRINT HELP PLEASE!" << std::endl; // TODO: USAGE/HELP
                break;
            }
            case 'r': {
                this->file_proccessing(optarg);
                break;
            }
            case 'i': {
                if (duplicity_interface && !this->duplicate_interface(std::string(optarg)))
                    break;
                this->is_interface_online(std::string(optarg));
                duplicity_interface = true;
                break;
            }
            case 's': {
                struct AddressWrapper syslog_server;
                syslog_server = this->syslog_address_proccessing(optarg);
                this->syslog_server_addr.push_back(syslog_server);
                break;
            }
            case 't': {
                if (duplicity_timeout && !this->duplicate_timeout(std::stod(optarg)))
                    break;
                this->time_in_seconds = std::stod(optarg);
                duplicity_timeout = true;
                break;
            }
            default: {
                std::cerr << "Argument error!" << endl;
                exit(-1);
            }
        }
    }
    this->print_arguments();
}