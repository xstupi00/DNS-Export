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


void ArgumentParser::parse_arguments(int argc, char **argv) {
    const char *const short_opts = "hr:i:s:t:";     ///< short forms of arguments
    const option long_opts[] = {                    ///< long forms of arguments
            {"pcap_file",     required_argument, nullptr, 'r'},
            {"interface",     required_argument, nullptr, 'i'},
            {"syslog_server", required_argument, nullptr, 's'},
            {"seconds",       required_argument, nullptr, 't'},
            {"help",          no_argument,       nullptr, 'h'},
            {nullptr, 0,                         nullptr, 0},
    };

    std::bitset<4> args_arr;    ///< auxiliary array to check the acceptable combinations of arguments
    time_in_seconds = 60;       ///< setting the default value of interval for sending the syslog messages

    int opt;
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'h': {     ///< printing of the manual page
                std::cout << "TODO: MANUAL PAGE!" << std::endl;
                exit(args_arr.any() ? EXIT_FAILURE : EXIT_SUCCESS);
            }
            case 'r': {     ///< pcap file processing
                if (args_arr.to_ulong() & 0x5) {    ///< check acceptable combinations
                    std::cerr << "Wrong combinations of arguments!" << std::endl;
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
                    std::cerr << "Wrong combinations of arguments!" << std::endl;
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
                    std::cerr << "Wrong combinations of arguments!" << std::endl;
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
                std::cerr << "Wrong combinations of arguments!" << std::endl;
                exit(EXIT_FAILURE);
            }
        }

        if (!(args_arr.to_ulong() &
              0x3)) { ///< offline and online mode commonly (pcap file and interface name was given)
            std::cerr << "Wrong combinations of arguments!" << std::endl;
            exit(EXIT_FAILURE);
        }
    }
}