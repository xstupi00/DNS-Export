/**************************************************************
 * Project:     DNS Export
 * File:		SyslogSender.h
 * Author:		Šimon Stupinský
 * University: 	Brno University of Technology
 * Faculty: 	Faculty of Information Technology
 * Course:	    Network Applications and Network Administration
 * Date:		28.09.2018
 * Last change:	16.11.2018
 *
 * Subscribe:	The header module of SyslogSender class, that insure sending the statistics to syslog server
 *
 **************************************************************/

/**
 * @file    SyslogServer.h
 * @brief   Declaration of methods that insures the sending statistics messages to syslog server.
 */

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

/**
 * SyslogSender class that create statistics messages and then it sending to given syslog server.
 */
class SyslogSender {
public:
    ///< Default constructor declaration
    SyslogSender();

    ///< Default destructor declaration
    ~SyslogSender();

    ///< file descriptor of socket to connect and send messages to server
    int socket_fd;

    /**
     * @brief   Method mainly implements sending the individual created messages to syslog servers. At the begin method
     *          obtains the addresses of given server, following create the socket with the needed parameters according
     *          to obtained address. In the next step calling the method, that create the individual messages to send
     *          from statistics and in the last step these messages will be send with use created socket.
     *
     * @param syslog_servers    vector with syslog servers where would be send the statistics
     * @param stats             statistics that would be send to syslog servers
     *
     * @return  methods has no return value
     */
    void send_to_server(std::vector<std::string> syslog_servers, std::unordered_map<std::string, int> stats);

    /**
     * @brief   Method generate the timestamp for syslog messages according to specific format, which is required by
     *          reference RFC for syslog.
     *
     * @param   method has not parameters
     *
     * @return  method returns created timestamp
     */
    std::string generate_timestamp();

    /**
     * @brief   Method obtaining the local address of machine from which will be sending the syslog messages. This
     *          obtaining is executed on the base of the created socket through which is local address obtained.
     *
     * @param ai_family     ai_family of created socket for communication wih syslog server
     *
     * @return  method returns obtained local address of actual machine
     */
    std::string get_local_hostname(int ai_family);

    /**
     * @brief   Method creating the messages from the given statistics with the specific format.
     *
     * @param stats     statistics from DNS sniffing (pcap file or online interface sniffing)
     * @param ai_family ai_family of created socket for communication with syslog server
     *
     * @return  method return the vector that contains the individual created messages to send
     */
    std::vector<std::string> create_msg(std::unordered_map<std::string, int> stats, int ai_family);
};

#endif //SYSLOGSENDER_H
