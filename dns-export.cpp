#include "DnsExport.h"

// https://www.tutorialspoint.com/cplusplus/cpp_signal_handling.htm

using namespace std;

DnsExport dns_export;

void signalHandler(int signum) {
    std::cout << "Interrupt signal (" << signum << ") received" << endl;

    dns_export.proccess_tcp_packets();
    for (std::pair<std::string, int> stats_item: dns_export.stats) {
        std::cout << stats_item.first << " " << stats_item.second << endl;
    }
}

int main(int argc, char **argv) {
    signal(SIGUSR1, signalHandler);
    dns_export.run(argc, argv);
}