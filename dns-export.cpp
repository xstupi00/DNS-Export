#include "DnsExport.h"
#include "SyslogSender.h"

DnsExport dns_export;

extern void handle_alarm_signal(int _) {
    UNUSED(_);  ///< ignoring gcc warning about the unused variable

    dns_export.proccess_tcp_packets();
    if (!syslog_servers.empty()) { ///< check whether syslog servers was given
        pid_t pid = fork();     ///< fork the main process

        if (pid == 0) { ///< child process going send stats to server
            ///< instantiation of Syslog Sender
            SyslogSender syslog_sender;
            ///< calling function that will send the stats to syslog
            syslog_sender.send_to_server(syslog_servers, stats);
            ///< kill the child process
            kill(getpid(), SIGTERM);
        } else if (pid > 0) {
            ///< set the new alarm for next round of sending stats to syslog server
            alarm(time_in_seconds);
            ///< back to the processing of packets
            return;
        } else {    ///< unsuccessful fork()
            std::cerr << "System Error: fork() failed" << std::endl;
            exit(EXIT_FAILURE);
        }
    } else {    ////< no syslog servers
        return;
    }

}

extern void handle_sigusr_signal(int _) {
    UNUSED(_);  ///< ignoring gcc warning about the unused variable

    dns_export.proccess_tcp_packets();  ///< processing of TCP Packets
    pid_t pid = fork();     ///< fork the main process

    if (pid == 0) {     ///< child process
        if (stats.empty()) {    ///< no caught DNS packets so far
            std::cout << "Empty stats! " << dns_export.tcp_packets.size() << std::endl;
        } else {        ///< stats is not empty
            for (std::pair<std::string, int> stats_item: stats) {
                std::cout << stats_item.first << " " << stats_item.second << std::endl;
            }
            std::cout << "------------------------------------------------------------------------------" << std::endl;
        }
        ///< kill the child process
        kill(getpid(), SIGTERM);
    } else if (pid > 0) {
        ///< back to the processing of packets
        return;
    } else {        ///< unsuccessful fork()
        std::cerr << "System Error: fork() failed" << std::endl;
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv) {
    ///< register the SIGUSR1 signal
    signal(SIGUSR1, handle_sigusr_signal);
    ///< run application
    dns_export.run(argc, argv);
}
