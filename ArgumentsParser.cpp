#include <bitset>
#include "ArgumentsParser.h"


/**
* Default Contructor.
*/
ArgumentParser::ArgumentParser() = default;

/**
* Destructor.
*/
ArgumentParser::~ArgumentParser() = default;


void ArgumentParser::parse_arguments(int argc, char **argv) {
    const char *const short_opts = "hr:i:s:t:";
    const option long_opts[] = {
            {"pcap_file",     required_argument, nullptr, 'r'},
            {"interface",     required_argument, nullptr, 'i'},
            {"syslog_server", required_argument, nullptr, 's'},
            {"seconds",       required_argument, nullptr, 't'},
            {"help",          no_argument,       nullptr, 'h'},
            {nullptr,         0,                 nullptr,  0 },
    };

    std::bitset<4> args_arr;

    int opt;
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, nullptr)) != -1) {
        switch (opt) {
            case 'h': {
                std::cout << "PRINT USAGE PLEASE!" << std::endl;
                exit(args_arr.any() ? EXIT_FAILURE : EXIT_SUCCESS);
            }
            case 'r': {
                if (args_arr.to_ulong() & 0b0101) {
                    std::cerr << "Wrong combinations of arguments!" << std::endl;
                    exit(EXIT_FAILURE);
                } else {
                    struct stat sb = {};
                    if (stat(optarg, &sb) == 0) {
                        this->pcap_files.emplace_back(optarg);
                    } else {
                        std::perror("stat() failed: ");
                    }
                }
                args_arr.set(0);
                break;
            }
            case 'i': {
                if (args_arr.test(0)) {
                    std::cerr << "Wrong combinations of arguments!" << std::endl;
                    exit(EXIT_FAILURE);
                } else {
                    args_arr.set(1);
                    this->interface_name = std::string(optarg);
                }
                break;
            }
            case 's': {
                args_arr.set(2);
                this->syslog_servers.emplace_back(optarg);
                break;
            }
            case 't': {
                if (args_arr.test(0)) {
                    std::cerr << "Wrong combinations of arguments!" << std::endl;
                    exit(EXIT_FAILURE);
                } else {
                    args_arr.set(3);
                    this->time_in_seconds = (unsigned) std::stoi(optarg);
                }
                break;
            }
            default: {
                std::cerr << "Wrong combinations of arguments!" << std::endl;
                exit(EXIT_FAILURE);
            }
        }

        if (!(args_arr.to_ulong() & 0b0011)) {
            std::cerr << "Wrong combinations of arguments!" << std::endl;
            exit(EXIT_FAILURE);
        }
    }
}