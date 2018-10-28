#include <iostream>
#include <sstream>
#include <zconf.h>
#include "SyslogSender.h"
#include "DataStructures.h"


/**
* Default Contructor.
*/
SyslogSender::SyslogSender() = default;


/**
* Destructor.
*/
SyslogSender::~SyslogSender() = default;


std::string SyslogSender::generate_timestamp() {

    const char *timestamp_format = "%04Y-%02m-%02dT%02H:%02M:%02S.";
    time_t rawtime;
    time(&rawtime);
    struct tm *timeinfo = gmtime(&rawtime);
    auto *outstr = (char *) malloc(200);
    if (strftime(outstr, 200, timestamp_format, timeinfo) == 0) {
        std::cerr << "strftime returned 0" << std::endl;
    }
    timeval t_val = {};
    if (gettimeofday(&t_val, nullptr) == -1) {
        std::cerr << "gettimeofday() failed: " << gai_strerror(errno) << std::endl;
    }

    std::string time_stamp = std::string(outstr);
    time_stamp.append(std::to_string(t_val.tv_usec).substr(0, 3));
    time_stamp.append("Z");

    return time_stamp;
}

std::string SyslogSender::get_local_hostname() {
    struct ifaddrs *ifAddrStruct = nullptr;
    struct ifaddrs *ifa = nullptr;
    void *tmpAddrPtr = nullptr;

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET and ifa->ifa_flags & IFF_RUNNING and
            !(ifa->ifa_flags & IFF_LOOPBACK)) { ///< check it is IP4
            ///< is a valid IP4 Address
            tmpAddrPtr = &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
            auto addressBuffer = new char[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            return addressBuffer;
        } else if (ifa->ifa_addr->sa_family == AF_INET6 and ifa->ifa_flags & IFF_RUNNING and
                   !(ifa->ifa_flags & IFF_LOOPBACK)) { ///< check it is IP6
            ///< is a valid IP6 Address
            tmpAddrPtr = &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr;
            auto addressBuffer = new char[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
            std::transform(addressBuffer, addressBuffer + INET6_ADDRSTRLEN, addressBuffer, ::toupper);
            return addressBuffer;
        }
    }
    if (ifAddrStruct != nullptr) freeifaddrs(ifAddrStruct);

    return nullptr;
}


///< http://proswdev.blogspot.com/2012/02/get-process-id-by-name-in-linux-using-c.html
long SyslogSender::get_first_proc_id_by_name(std::string proc_name) {
    long pid = -1;

    // Open the /proc directory
    DIR *dp = opendir("/proc");
    if (dp != nullptr) {
        // Enumerate all entries in directory until process found
        struct dirent *dirp;
        while (pid < 0 && (dirp = readdir(dp))) {
            // Skip non-numeric entries
            long id = strtol(dirp->d_name, nullptr, 10);
            if (id > 0) {
                // Read contents of virtual /proc/{pid}/cmdline file
                std::string cmdPath = std::string("/proc/") + dirp->d_name + "/cmdline";
                std::ifstream cmdFile(cmdPath.c_str());
                std::string cmdLine;
                getline(cmdFile, cmdLine);
                if (!cmdLine.empty()) {
                    // Keep first cmdline item which contains the program path
                    size_t pos = cmdLine.find('\0');
                    if (pos != std::string::npos)
                        cmdLine = cmdLine.substr(0, pos);
                    // Keep program name only, removing the path
                    pos = cmdLine.rfind('/');
                    if (pos != std::string::npos)
                        cmdLine = cmdLine.substr(pos + 1);
                    // Compare against requested process name
                    if (proc_name == cmdLine)
                        pid = id;
                }
            }
        }
    }

    closedir(dp);

    return pid;
}

std::string SyslogSender::create_header() {
    std::string app_name = "dns-export";
    std::stringstream msg;
    msg << "<" << LOG_MAKEPRI(LOG_LOCAL0, LOG_INFO) << ">1 " << this->generate_timestamp() << " "
        << this->get_local_hostname() << " " << app_name << " " << this->get_first_proc_id_by_name(app_name)
        << " - - ";

    return msg.str();
}

void SyslogSender::send_msg_to_server(std::vector<struct AddressWrapper> syslog_servers, std::string msg) {

    std::cout << "SENDING MSG = " << msg.size() << std::endl;

    for (struct AddressWrapper &syslog_server : syslog_servers) {
        if (!syslog_server.addr_IPv4.empty()) {
            for (struct sockaddr_in &addr_IPv4 : syslog_server.addr_IPv4) {
                int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                addr_IPv4.sin_port = htons(514);

                ssize_t s = sendto(fd, msg.c_str(), msg.length(), 0, (struct sockaddr *) &addr_IPv4, sizeof(addr_IPv4));
                if (s < 0) {
                    std::cerr << "sendto failed" << gai_strerror(s) << std::endl;
                } else {
                    break;
                }
            }
        } else if (!syslog_server.addr_IPv6.empty()) {
            for (struct sockaddr_in6 &addr_IPv6 : syslog_server.addr_IPv6) {
                int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
                addr_IPv6.sin6_port = htons(514);

                ssize_t s = sendto(fd, msg.c_str(), msg.length(), 0, (struct sockaddr *) &addr_IPv6, sizeof(addr_IPv6));
                if (s < 0) {
                    std::cerr << "sendto failed" << gai_strerror(s) << std::endl;
                } else {
                    break;
                }
            }
        }
    }
}

void SyslogSender::sending_stats(std::vector<struct AddressWrapper> syslog_servers,
                                 std::unordered_map<std::string, int> stats) {
    std::string header = this->create_header();
    std::stringstream msg;
    msg << header;
    bool not_send = true;
    for (std::pair<std::string, int> stats_item : stats) {
        not_send = true;
        if (msg.str().size() + stats_item.first.size() + sizeof(int) <= 1024) { // 1KiB
            msg << stats_item.first << " " << stats_item.second << std::endl;
        } else {
            this->send_msg_to_server(syslog_servers, msg.str());
            std::cout << msg.str() << std::endl;
            header = this->create_header();
            msg.str(""); msg.clear();
            msg << header << stats_item.first << " " << stats_item.second << std::endl;
            not_send = false;
        }
    }
    if (not_send) {
        this->send_msg_to_server(syslog_servers, msg.str());
        std::cout << msg.str() << std::endl;
    }

    //std::cout << "I'm going to sleep (10 seconds). Good night Simon" << std::endl;
    //sleep(10);
    //std::cout << "Good morning Simon!" << std::endl;
}

