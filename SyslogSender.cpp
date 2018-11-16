#include "SyslogSender.h"

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
    timeval t_val;
    if (gettimeofday(&t_val, nullptr) == -1) {
        std::cerr << "gettimeofday() failed: " << gai_strerror(errno) << std::endl;
    }

    std::string time_stamp = std::string(outstr);
    time_stamp.append(std::to_string(t_val.tv_usec).substr(0, 3));
    time_stamp.append("Z");

    return time_stamp;
}

std::string SyslogSender::get_local_hostname(int ai_family) {

    std::string local_addr;

    if (ai_family == AF_INET) {
        char localhost[INET_ADDRSTRLEN];
        struct sockaddr_in my_addr;

        bzero(&my_addr, sizeof(my_addr));
        socklen_t len = sizeof(my_addr);
        if (getsockname(this->socket_fd, (struct sockaddr *) &my_addr, &len) == -1) {
            std::perror("getsockname() failed");
        }

        if (inet_ntop(AF_INET, &(my_addr.sin_addr), localhost, sizeof(localhost)) == nullptr) {
            std::perror("inet_ntop");
        };
        local_addr = std::string(localhost);
    } else if (ai_family == AF_INET6) {
        char localhost[INET6_ADDRSTRLEN];
        struct sockaddr_in6 my_addr;

        bzero(&my_addr, sizeof(my_addr));
        socklen_t len = sizeof(my_addr);
        if (getsockname(this->socket_fd, (struct sockaddr *) &my_addr, &len) == -1) {
            std::perror("getsockname() failed");
        }

        if (inet_ntop(AF_INET6, &(my_addr.sin6_addr), localhost, sizeof(localhost)) == nullptr) {
            std::perror("inet_ntop");
        };
        local_addr = std::string(localhost);
    }

    return local_addr;
}

void
SyslogSender::send_to_server(std::vector<std::string> syslog_servers, std::unordered_map<std::string, int> stats) {
    struct addrinfo hints, *result, *rp;
    std::vector<std::string> messages;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    for (std::string &syslog_server : syslog_servers) {
        int s = getaddrinfo(syslog_server.c_str(), "syslog", &hints, &result);
        if (s != 0) {
            std::cerr << "getaddrinfo: " << gai_strerror(s) << std::endl;
        } else {
            for (rp = result; rp != nullptr; rp = rp->ai_next) {
                if ((this->socket_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) < 0) {
                    std::perror("socket() failed");
                } else {
                    if (connect(this->socket_fd, rp->ai_addr, rp->ai_addrlen) == -1) {
                        std::perror("connect() failed");
                    }

                    messages = this->create_msg(stats, rp->ai_family);
                    bool send_failure = false;
                    for (std::string &msg : messages) {
                        ssize_t s1 = send(this->socket_fd, msg.c_str(), msg.length(), 0);
                        if (s1 < 0) {
                            std::perror("sendto() failed");
                            send_failure = true;
                            break;
                        }
                    }
                    if (!send_failure) break;
                }
            }
        }
        freeaddrinfo(result);
    }
}

std::vector<std::string> SyslogSender::create_msg(std::unordered_map<std::string, int> stats, int ai_family) {

    std::stringstream msg;
    std::vector<std::string> messages;
    msg << "<" << LOG_MAKEPRI(LOG_LOCAL0, LOG_INFO) << ">1 " << this->generate_timestamp() << " "
        << this->get_local_hostname(ai_family) << " dns-export" << " " << getpid() << " - - ";

    for (std::pair<std::string, int> stats_item : stats) {
        if (msg.str().size() + stats_item.first.size() + sizeof(stats_item.second) <= 1024) {
            msg << stats_item.first << " " << stats_item.second << std::endl;
        } else {
            messages.emplace_back(msg.str());
            msg.str("");
            msg.clear();
            msg << "<" << LOG_MAKEPRI(LOG_LOCAL0, LOG_INFO) << ">1 " << this->generate_timestamp() << " "
                << this->get_local_hostname(ai_family) << " dns-export" << " " << getpid() << " - - ";
        }
    }
    if (!msg.str().empty()) {
        messages.emplace_back(msg.str());
    }

    return messages;
}
