/**************************************************************
 * Project:     DNS Export
 * File:		ArgumentParser.h
 * Author:		Šimon Stupinský
 * University: 	Brno University of Technology
 * Faculty: 	Faculty of Information Technology
 * Course:	    Network Applications and Network Administration
 * Date:		28.09.2018
 * Last change:	16.11.2018
 *
 * Subscribe:	The header module of the ArgumentParser class
 *
 **************************************************************/

/**
 * @file    ArgumentParser.h
 * @brief   Declaration of methods and attributes for ArgumentParser class
 */

#ifndef ARGUMENTSPARSER_H
#define ARGUMENTSPARSER_H

#include <bitset>
#include <getopt.h>
#include <iostream>
#include <sys/stat.h>
#include <vector>

///< global variables to access in the signal handlers
extern unsigned time_in_seconds;                    ///< interval for sending messages to syslog server
extern std::vector<std::string> syslog_servers;     ///< vector of syslog servers for sending stats

/**
 * ArgumentParser class to processing of arguments from the command line.
 */
class ArgumentParser {
public:
    ///< Default constructor declaration
    ArgumentParser();

    ///< Default destructor declaration
    ~ArgumentParser();

    std::vector<std::string> pcap_files;    ///< pcap_files for processing - offline sniffing mode
    std::string interface_name = "any";     ///< interface name for listening - online sniffing mode

    /**
     * @brief   Main method to process of arguments from command line. Method obtains the arguments with using the
     *      getopt() function. During the obtaining of arguments also check the correctness of its format and the
     *      acceptable combinations of arguments.
     *
     * @param argc  count of the arguments
     * @param argv  array with the arguments
     *
     * @return method has no return value
     */
    void parse_arguments(int argc, char **argv);
};

#endif //ARGUMENTSPARSER_H