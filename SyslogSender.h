#ifndef SYSLOGSENDER_H
#define SYSLOGSENDER_H

#include <unordered_map>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <algorithm>
#include <netdb.h>
#include <syslog.h>
#include <dirent.h>
#include <sys/time.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <sstream>

class SyslogSender {
public:
    SyslogSender();

    ~SyslogSender();

    void sending_stats(std::vector<struct AddressWrapper> syslog_servers, std::unordered_map<std::string, int> stats);

    std::string generate_timestamp();

    std::string get_local_hostname();

    void send_msg_to_server(std::vector<struct AddressWrapper> syslog_servers, std::string msg);

    size_t nth_substr(int n, const std::string& s, const std::string& p);

    int socket_fd;

};

#endif //SYSLOGSENDER_H
