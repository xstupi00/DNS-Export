//
// Created by Simon Stupinsky on 28/09/2018.
//

#ifndef UNTITLED_ARGUMENTSPARSER_H
#define UNTITLED_ARGUMENTSPARSER_H

#include "DnsExport.h"

using namespace std;


class ArgumentParser: public DnsExport
{
    public:
        ArgumentParser();
        ~ArgumentParser();

        void parse_arguments(int argc, char**argv);

    private:
        inline void file_proccessing(const std::string& name);
        inline void syslog_address_proccessing(const std::string& addr);
};


#endif //UNTITLED_ARGUMENTSPARSER_H
