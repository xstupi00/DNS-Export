/**************************************************************
 * Project:     DNS Export
 * File:		ArgumentParser.cpp
 * Author:		Šimon Stupinský
 * University: 	Brno University of Technology
 * Faculty: 	Faculty of Information Technology
 * Course:	    Network Applications and Network Administration
 * Date:		28.09.2018
 * Last change:	16.11.2018
 *
 * Subscribe:	The main module of the ArgumentParser class.
 *
 **************************************************************/

/**
 * @file    ArgumentParser.h
 * @brief   Executing the processing of the arguments and its storing.
 */


#include "ArgumentsParser.h"


/**
* Default Constructor.
*/
ArgumentParser::ArgumentParser() = default;

/**
* Destructor.
*/
ArgumentParser::~ArgumentParser() = default;

void print_help() {
    std::cerr
            << "dns-export:  process DNS (Domain Name System) protocol data and export it to central "
                    "logging server using Syslog protocol.\n"
                    "Usage:   dns-export [-r FILE.PCAP] [--pcap_file FILE.PCAP] [-i INTERFACE] "
                    "[--interface INTERFACE] \n"
                    "                    [-s  SYSLOG-SERVER]  [--syslog SYSLOG-SERVER] [-t SECONDS] "
                    "[--time SECONDS]\n\n"
                    "              -h, --help\n"
                    "                       Print the the usage of application and exit.\n"
                    "\n"
                    "              -r, --pcap_file=FILE.PCAP\n"
                    "                       Processing of the given FILE.PCAP and create stats from DNS "
                    "protocol data, stored in it.\n"
                    "                       This option can't be used in combination with -i or -t.\n"
                    "\n"
                    "              -i, --interface=INTERFACE\n"
                    "                       Listen on given INTERFACE and process DNS traffic.\n"
                    "                       This option can't be used in combination  with  -r.\n  "
                    "                     Default value is any.\n"
                    "\n"
                    "              -s, --syslog=SYSLOG-SERVER\n"
                    "                       Syslog server given by IPv4/IPv6/Hostname where the statistics "
                    "will be send.\n"
                    "\n"
                    "              -t, --time=SECONDS\n"
                    "                       SECONDS is time while stats will be computed.\n"
                    "                       Default value is 60s.\n"
                    "                       This option can't be used in combination with -r and must be "
                    "used in combination with -s.\n"
            << std::endl;
}


void ArgumentParser::parse_arguments(int argc, char **argv) {
    const char *const short_opts = "hr:i:s:t:";     ///< short forms of arguments
    const option long_opts[] = {                    ///< long forms of arguments
            {"pcap_file", required_argument, nullptr, 'r'},
            {"interface", required_argument, nullptr, 'i'},
            {"syslog",    required_argument, nullptr, 's'},
            {"time",      required_argument, nullptr, 't'},
            {"help",      no_argument,       nullptr, 'h'},
            {nullptr, 0,                     nullptr, 0},
    };

    std::bitset<4> args_arr;    ///< auxiliary array to check the acceptable combinations of arguments
    time_in_seconds = 60;       ///< setting the default value of interval for sending the syslog messages

    int opt;
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'h': {     ///< printing of the manual page
                print_help();
                exit(args_arr.any() ? EXIT_FAILURE : EXIT_SUCCESS);
            }
            case 'r': {     ///< pcap file processing
                if (args_arr.test(1) or args_arr.test(3)) {    ///< check acceptable combinations
                    std::cerr << "Wrong combinations of arguments!" << std::endl << std::endl;
                    print_help();
                    exit(EXIT_FAILURE);
                } else {
                    struct stat sb;
                    ///< check whether the file exists
                    if (stat(optarg, &sb) == 0) {
                        ///< sets the flag for pcap file argument
                        args_arr.set(0);
                        ///< store the pcap_file name
                        this->pcap_files.emplace_back(optarg);
                    } else {    ///< if file doesn't exists, the program ending with the failure code
                        std::perror("stat() failed: ");
                        exit(EXIT_FAILURE);
                    }
                }
                break;
            }
            case 'i': {     ///< interface name processing
                if (args_arr.test(0)) {             ///< check acceptable combinations
                    std::cerr << "Wrong combinations of arguments!" << std::endl << std::endl;
                    print_help();
                    exit(EXIT_FAILURE);
                } else {
                    ///< sets the flag for interface name argument
                    args_arr.set(1);
                    ///< store the interface name
                    this->interface_name = std::string(optarg);
                }
                break;
            }
            case 's': {     ///< syslog server name processing
                ///< store the syslog server name (correctness will be checked later)
                syslog_servers.emplace_back(optarg);
                ///< sets the flag for syslog server argument
                args_arr.set(2);
                break;
            }
            case 't': {     ///< time in seconds argument processing
                if (args_arr.test(0)) {             ///< check acceptable combinations
                    std::cerr << "Wrong combinations of arguments!" << std::endl << std::endl;
                    print_help();
                    exit(EXIT_FAILURE);
                } else {
                    ///< store interval for sending the syslog messages
                    time_in_seconds = (unsigned) std::stoi(optarg);
                    ///< sets the flag for time argument
                    args_arr.set(3);
                }
                break;
            }
            default: {      ///< unknown arguments
                std::cerr << "Wrong combinations of arguments!" << std::endl << std::endl;
                print_help();
                exit(EXIT_FAILURE);
            }
        }
    }

    ///< wrong combinations of arguments
    if (!args_arr.test(2) and args_arr.test(3)) {
        std::cerr << "Wrong combinations of arguments!" << std::endl << std::endl;
        print_help();
        exit(EXIT_FAILURE);
    }
}