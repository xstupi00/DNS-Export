#ifndef SYSLOGSENDER_H
#define SYSLOGSENDER_H

#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <sstream>
#include <syslog.h>
#include <sys/time.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

class SyslogSender {
public:
    SyslogSender();

    ~SyslogSender();

    void send_to_server(std::vector<std::string> syslog_servers, std::unordered_map<std::string, int> stats);

    std::string generate_timestamp();

    std::string get_local_hostname(int ai_family);

    std::vector<std::string> create_msg(std::unordered_map<std::string, int> stats, int ai_family);

    int socket_fd;

};

#endif //SYSLOGSENDER_H
