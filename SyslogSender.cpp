#include <zconf.h>
#include <strings.h>
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

    char localhost[INET_ADDRSTRLEN];
    struct sockaddr_in my_addr = {};

    bzero(&my_addr, sizeof(my_addr));
    socklen_t len = sizeof(my_addr);
    if (getsockname(this->socket_fd, (struct sockaddr *)&my_addr, &len) == -1) {
        std::perror("getsockname() failed");
    }

    if (inet_ntop(AF_INET, &(my_addr.sin_addr), localhost, sizeof(localhost)) == nullptr) {
        std::perror("inet_ntop");
    };

    return std::string(localhost);
}

size_t SyslogSender::nth_substr(int n, const std::string& s, const std::string& p) {
    int j;

    std::string::size_type i = s.find(p);
    for (j = 1; j < n && i != std::string::npos; ++j) {
        i = s.find(p, i + p.length());
    }

    return i;
}

void SyslogSender::send_msg_to_server(std::vector<struct AddressWrapper> syslog_servers, std::string msg) {

    //std::cout << "SENDING MSG = " << msg.size() << std::endl;

    for (struct AddressWrapper &syslog_server : syslog_servers) {
        if (!syslog_server.addr_IPv4.empty()) {
            for (struct sockaddr_in &addr_IPv4 : syslog_server.addr_IPv4) {
                if ((this->socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
                    std::perror("socket() failed");
                } else {
                    addr_IPv4.sin_port = htons(514);
                    if (connect(this->socket_fd, (struct sockaddr *) &addr_IPv4, sizeof(addr_IPv4)) == -1) {
                        std::perror("connect() failed");
                    }
                    msg.insert(this->nth_substr(2, msg, " ")+1, this->get_local_hostname()+" ");
                    //std::cout << msg << std::endl;
                    ssize_t s = send(this->socket_fd, msg.c_str(), msg.length(), 0);
                    if (s < 0) {
                        std::perror("sendto() failed");
                    } else {
                        break;
                    }
                }
            }
        } else if (!syslog_server.addr_IPv6.empty()) {
            for (struct sockaddr_in6 &addr_IPv6 : syslog_server.addr_IPv6) {
                if ((this->socket_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
                    std::perror("socket() failed");
                } else {
                    addr_IPv6.sin6_port = htons(514);
                    if (connect(this->socket_fd, (struct sockaddr *) &addr_IPv6, sizeof(addr_IPv6)) == -1) {
                        std::perror("connect() failed");
                    }
                    msg.insert(this->nth_substr(2, msg, " ")+1, this->get_local_hostname()+" ");
                    ssize_t s = send(this->socket_fd, msg.c_str(), msg.length(), 0);
                    if (s < 0) {
                        std::perror("sendto() failed");
                    } else {
                        break;
                    }
                }
            }
        }
    }
}

void SyslogSender::sending_stats(std::vector<struct AddressWrapper> syslog_servers,
                                 std::unordered_map<std::string, int> stats) {
    std::stringstream msg;
    msg << "<" << LOG_MAKEPRI(LOG_LOCAL0, LOG_INFO) << ">1 " << this->generate_timestamp() << " " << "dns-export" << " "
        << getpid() << " - - ";

    bool not_send = true;
    for (std::pair<std::string, int> stats_item : stats) {
        not_send = true;
        if (msg.str().size() + stats_item.first.size() + sizeof(stats_item.second) + INET_ADDRSTRLEN <= 1024) {
            msg << stats_item.first << " " << stats_item.second << std::endl;
        } else {
            this->send_msg_to_server(syslog_servers, msg.str());
            msg.str(""); msg.clear();
            msg << "<" << LOG_MAKEPRI(LOG_LOCAL0, LOG_INFO) << ">1 " << this->generate_timestamp() << " "
                << "dns-export" << " " << getpid() << " - - " << stats_item.first << " " << stats_item.second
                << std::endl;
            not_send = false;
        }
    }
    if (not_send) {
        this->send_msg_to_server(syslog_servers, msg.str());
    }
}


