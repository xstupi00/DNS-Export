#include "DnsExport.h"

DnsExport dns_export;

void signal_handler(int _) {
    UNUSED(_);
    pid_t pid = fork();

    if (pid == 0) {
        dns_export.proccess_tcp_packets();
        for (std::pair<std::string, int> stats_item: dns_export.stats) {
            std::cout << stats_item.first << " " << stats_item.second << std::endl;
        }
        std::cout << std::endl;
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
