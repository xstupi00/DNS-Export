#include "DnsExport.h"

DnsExport dns_export;

void signal_handler(int _) {
    UNUSED(_);
    dns_export.proccess_tcp_packets();
    pid_t pid = fork();

    if (pid == 0) {
        if (stats.empty()) {
            std::cout << "Empty stats! " << dns_export.tcp_packets.size() << std::endl;
        } else {
            for (std::pair<std::string, int> stats_item: stats) {
                std::cout << stats_item.first << " " << stats_item.second << std::endl;
            }
            std::cout << std::endl;
        }
        kill(getpid(), SIGTERM);
        return;
    } else if (pid > 0) {
        return;
    } else {
        std::cerr << "System Error: fork() failed" << std::endl;
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv) {
    signal(SIGUSR1, signal_handler);
    dns_export.run(argc, argv);
}
