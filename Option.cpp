#include "Option.h"
#include <iostream>
#include <map>

using namespace std;

void EchoHelp(void)
{
    cout << "Usage: \n\t";
    cout << "./sniffer [-i interface] [-t type] [-c count] [--sip address] [--dip address] [--sport port] [--dprot port] " << "\n\n";
    cout << "Optional parameters:\n\t";
    cout << "-i\t\t(number)to capture data interface\n\t";
    cout << "-t\t\tprotocol type(tcp/udp/icmp)\n\t";
    cout << "-c\t\tthe number of captured packets\n\t";
    cout << "--sip\t\tsource ip address\n\t";
    cout << "--dip\t\tdestination ip address\n\t";
    cout << "--sprot\t\tsource port(0-65535)\n\t";
    cout << "--dprot\t\tdestination port(0-65535)\n\t";
    cout << "--intera\t\tinteractive mode\n\t";
    cout << "--help\t\t(mutex)help information\n";
}

bool ArgIfLegal(int argc, char *argv[], string &bpfexpr, string &devname, int &count)
{
    // cmd --help
    if(argc == 2)
    { 
        if(argv[argc-1] != string("--help") && argv[argc-1] != string("--intera"))
            return false;
        else if(argv[argc-1] == string("--intera"))
            Interactive();
        else 
            EchoHelp();
        exit(0);
    }
    
    // 没有参数后者参数个数不匹配,正确的格式argc应该是单数
    if(argc == 1 || argc % 2 == 0)
        return false;

    map<string, int> options;

    options.insert(pair<string, int>("-i", 0));
    options.insert(pair<string, int>("-c", 1));
    options.insert(pair<string, int>("-t", 2));
    options.insert(pair<string, int>("--sip", 3));
    options.insert(pair<string, int>("--dip", 4));
    options.insert(pair<string, int>("--sport", 5));
    options.insert(pair<string, int>("--dport", 6));
    
    uint8_t numberFlag = 0;

    for(int i = 1; i < argc; i++)
    {
        try{
            switch(options.at(argv[i]))
            {
                // 网卡必选项
                case 0:
                    numberFlag |= 0x01;
                    i++;
                    devname = argv[i];
                    continue;
                case 1:
                    i++;
                    try{
                        count = stoi(argv[i]);
                    }
                    catch(...){
                        return false;
                    }
                    continue;
                case 2:
                    i++;
                    bpfexpr += "&& ";
                    bpfexpr += argv[i];
                    bpfexpr += " ";
                    continue;
                case 3:
                    i++;
                    bpfexpr += "&& src host ";
                    bpfexpr += argv[i];
                    bpfexpr += " ";
                    continue;
                case 4:
                    i++;
                    bpfexpr += "&& dst host ";
                    bpfexpr += argv[i];
                    bpfexpr += " ";
                    continue;
                case 5:
                    i++;
                    bpfexpr += "&& src port ";
                    bpfexpr += argv[i];
                    bpfexpr += " ";
                    continue;
                case 6:
                    i++;
                    bpfexpr += "&& dst port ";
                    bpfexpr += argv[i];
                    bpfexpr += " ";
                    continue;
            }
        }
        catch (const out_of_range &orr){
            return false; 
        }
    }

    if(numberFlag != 0x01)
        return false;

    bpfexpr.erase(0,3);

    return true;
}
