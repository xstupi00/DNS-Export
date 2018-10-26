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

class SyslogSender {
public:
    SyslogSender();

    ~SyslogSender();

    void sending_stats(std::vector<struct AddressWrapper> syslog_servers, std::unordered_map<std::string, int> stats);

    std::string generate_timestamp();

    std::string get_local_hostname();

    long get_first_proc_id_by_name(std::string proc_name);

    std::stringstream create_header();

    void send_msg_to_server(std::vector<struct AddressWrapper> syslog_servers, std::string msg);

};

#endif //SYSLOGSENDER_H
