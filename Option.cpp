#include "Option.h"
#include "Interface.h"
#include <iostream>
#include <map>

using namespace std;

// 打印邦族
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
    cout << "--sendtcp\t\tSend fake TCP packet\n\t";
    cout << "--help\t\t(mutex)help information\n";
}

bool ArgIfLegal(int argc, char *argv[], string &devname, string &bpfexpr, int &count, pcap_handler funptr)
{
    map<string, int> options;
    options.insert(pair<string, int>("-i", 0));
    options.insert(pair<string, int>("-c", 1));
    options.insert(pair<string, int>("-t", 2));
    options.insert(pair<string, int>("--sip", 3));
    options.insert(pair<string, int>("--dip", 4));
    options.insert(pair<string, int>("--sport", 5));
    options.insert(pair<string, int>("--dport", 6));
    options.insert(pair<string, int>("--intera", 7));
    options.insert(pair<string, int>("--sendtcp", 8));
    options.insert(pair<string, int>("--help", 9));


    bool devflag = false;

    for(int i = 1; i < argc; i++)
    {
        try{
            switch(options.at(argv[i]))
            {
                // 网卡必选项
                case 0:
                    devflag = true;
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
                    cout << bpfexpr << endl;
                    continue;
                case 3:
                    i++;
                    bpfexpr += "&& src host ";
                    bpfexpr += argv[i];
                    bpfexpr += " ";
                    cout << bpfexpr << endl;
                    continue;
                case 4:
                    i++;
                    bpfexpr += "&& src host ";
                    bpfexpr += "&& dst host ";
                    bpfexpr += argv[i];
                    bpfexpr += " ";
                    cout << bpfexpr << endl;
                    continue;
                case 5:
                    i++;
                    bpfexpr += "&& src port ";
                    bpfexpr += argv[i];
                    bpfexpr += " ";
                    cout << bpfexpr << endl;
                    continue;
                case 6:
                    i++;
                    bpfexpr += "&& dst port ";
                    bpfexpr += argv[i];
                    bpfexpr += " ";
                    cout << bpfexpr << endl;
                    continue;
                case 7:
                    // 调用交互模式
                    if(argc != 2)
                        return false;
                    interface(funptr);
                    exit(0);
                    break;
                case 8:
                    // 调用发送TCP
                    if(argc != 2)
                        return false;
                    cout << "发送TCP报文\n";
                    exit(0);
                    break;
                case 9:
                    // 调用打印帮助信息
                    if(argc != 2)
                        return false;
                    EchoHelp();
                    exit(0);
                    break;
            }
        }
        catch (const out_of_range &orr){
            return false; 
        }
    }

    if(devflag == false)
        return false;

    bpfexpr.erase(0, 3);
    
    cout << "bpfexpr = " << bpfexpr << endl;

    return true;
} 
