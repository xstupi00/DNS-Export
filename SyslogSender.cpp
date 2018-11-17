/**************************************************************
 * Project:     DNS Export
 * File:		SyslogSender.cpp
 * Author:		Šimon Stupinský
 * University: 	Brno University of Technology
 * Faculty: 	Faculty of Information Technology
 * Course:	    Network Applications and Network Administration
 * Date:		28.09.2018
 * Last change:	16.11.2018
 *
 * Subscribe:	The main module of SyslogSender class, that insure sending the statistics to syslog server.
 *
 **************************************************************/

/**
 * @file    SyslogServer.cpp
 * @brief   Module implements method that insure sending statistics messages to given syslog servers.
 */

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

    ///< specific format defined by [RFC5424] for timestamp that are sending in the syslog messages
    const char *timestamp_format = "%04Y-%02m-%02dT%02H:%02M:%02S.";

    ///< obtaining the actual time in UTC format
    time_t rawtime;
    time(&rawtime);
    struct tm *timeinfo = gmtime(&rawtime);
    auto *outstr = (char *) malloc(200);
    if (strftime(outstr, 200, timestamp_format, timeinfo) == 0) {
        std::cerr << "strftime returned 0" << std::endl;
    }

    ///< obtaining the value of time in microseconds for the last part of generated timestamp
    timeval t_val;
    if (gettimeofday(&t_val, nullptr) == -1) {
        std::cerr << "gettimeofday() failed: " << gai_strerror(errno) << std::endl;
    }

    ///< adding the obtained microseconds to the final timestamp
    std::string time_stamp = std::string(outstr);
    time_stamp.append(std::to_string(t_val.tv_usec).substr(0, 3));
    time_stamp.append("Z");

    return time_stamp;
}

std::string SyslogSender::get_local_hostname(int ai_family) {

    std::string local_addr;

    if (ai_family == AF_INET) {
        ///< communication through IPv4 addresses
        char localhost[INET_ADDRSTRLEN];
        struct sockaddr_in my_addr;
        bzero(&my_addr, sizeof(my_addr));
        socklen_t len = sizeof(my_addr);

        ///< obtaining the local address (IPv4) through which will socket communicate
        if (getsockname(this->socket_fd, (struct sockaddr *) &my_addr, &len) == -1) {
            std::perror("getsockname() failed");
        }

        ///< convert IPv4 address from binary to text form
        if (inet_ntop(AF_INET, &(my_addr.sin_addr), localhost, sizeof(localhost)) == nullptr) {
            std::perror("inet_ntop");
        };

        ///< set the return value of method
        local_addr = std::string(localhost);
    } else if (ai_family == AF_INET6) {
        ///< communication through IPv6 addresses
        char localhost[INET6_ADDRSTRLEN];
        struct sockaddr_in6 my_addr;
        bzero(&my_addr, sizeof(my_addr));
        socklen_t len = sizeof(my_addr);

        ///< obtaining the local address (IPv6) through which will socket communicate
        if (getsockname(this->socket_fd, (struct sockaddr *) &my_addr, &len) == -1) {
            std::perror("getsockname() failed");
        }

        ///< convert IPv6 address from binary to text form
        if (inet_ntop(AF_INET6, &(my_addr.sin6_addr), localhost, sizeof(localhost)) == nullptr) {
            std::perror("inet_ntop");
        };

        ///< set the return value of method
        local_addr = std::string(localhost);
    }

    return local_addr;
}

void
SyslogSender::send_to_server(std::vector<std::string> syslog_servers, std::unordered_map<std::string, int> stats) {
    struct addrinfo hints, *result, *rp;
    ///< vector for storing the created messages
    std::vector<std::string> messages;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    ///< unspecified address family, will be assigned according to created socket
    hints.ai_socktype = SOCK_DGRAM; ///< UDP communication

    ///< send the statistics to all given syslog server - ony by one
    for (std::string &syslog_server : syslog_servers) {
        ///< obtaining the addresses of the individual syslog server
        int s = getaddrinfo(syslog_server.c_str(), "syslog", &hints, &result);
        if (s != 0) {   ///< some error has occurred at obtaining the addresses of servers
            std::cerr << "getaddrinfo: " << gai_strerror(s) << std::endl;
        } else {
            ///< will testing every address until it is one successful
            for (rp = result; rp != nullptr; rp = rp->ai_next) {
                ///< socket creating according to server address specification
                if ((this->socket_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) < 0) {
                    std::perror("socket() failed");
                } else {
                    ///< connect to the server
                    if (connect(this->socket_fd, rp->ai_addr, rp->ai_addrlen) == -1) {
                        std::perror("connect() failed");
                    }
                    ///< calling the method that creating the vector with syslog messages
                    messages = this->create_msg(stats, rp->ai_family);

                    bool send_failure = false;  ///< auxiliary flag for detection unsuccessful sending to server
                    for (std::string &msg : messages) {     ///< send all messages from the created vector
                        ///< send message to syslog serevr
                        ssize_t s1 = send(this->socket_fd, msg.c_str(), msg.length(), 0);
                        if (s1 < 0) {   ///< some error has occurred at sending to syslog server
                            std::perror("sendto() failed");
                            send_failure = true;    ///< set failure flag
                            break;                  ///< stop the next sending
                        }
                    }
                    if (!send_failure) break;   ///< successful sending it will continue with next syslog server
                }   ///< end sending branch
            }   ///< end address loop
        }   ///< successful obtaining the server addresses
    }   ///< end syslog servers loop
}   ///< end methods

std::vector<std::string> SyslogSender::create_msg(std::unordered_map<std::string, int> stats, int ai_family) {

    std::stringstream msg;  ///< individual message for storing to the vector
    std::vector<std::string> messages;  ///< vector of syslog messages

    ///< formatting the introduction fields of message according to given specification and [RFC5424]
    msg << "<" << LOG_MAKEPRI(LOG_LOCAL0, LOG_INFO) << ">1 " << this->generate_timestamp() << " "
        << this->get_local_hostname(ai_family) << " dns-export" << " " << getpid() << " - - ";

    ///< folding the statistics items to the syslog message
    for (std::pair<std::string, int> stats_item : stats) {
        ///< available capacity in the creating message
        if (msg.str().size() + stats_item.first.size() + sizeof(stats_item.second) <= 1024) {
            msg << stats_item.first << " " << stats_item.second << std::endl;
        } else {    ///< the capacity of message is full and the message have to be insert to the vector
            ///< insert message to the vector
            messages.emplace_back(msg.str());
            ///< clear the content of message
            msg.str("");
            ///< clear the message flag
            msg.clear();
            ///< create the new header for the next message
            msg << "<" << LOG_MAKEPRI(LOG_LOCAL0, LOG_INFO) << ">1 " << this->generate_timestamp() << " "
                << this->get_local_hostname(ai_family) << " dns-export" << " " << getpid() << " - - ";
        }
    }
    ///< insert the last message in the case when the capacity is still available
    if (!msg.str().empty()) {
        messages.emplace_back(msg.str());
    }

    return messages;
}
