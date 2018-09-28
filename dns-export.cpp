#include <iostream>
#include <csignal>
#include <unistd.h>

#include "DnsExport.h"

// https://www.tutorialspoint.com/cplusplus/cpp_signal_handling.htm

using namespace std;

void signalHandler( int signum ) {
    cout << endl <<"Interrupt signal (" << signum << ") received" << endl;

    // cleanup and close up stuff here
    // terminate program

    exit(signum);
}

int main (int argc, char **argv) {
    DnsExport dns_export;
    dns_export.run(argc, argv);
    // register signal SIGINT and signal handler
    // will be changed to SIGUSR1
    signal(SIGINT, signalHandler);
    //for(;;) ;
}