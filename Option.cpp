#include "Option.h"
#include "Interface.h"
#include "SendTcp.h"
#include <iostream>
#include <map>

using namespace std;

// 打印帮助
void EchoHelp(void)
{
    cout << "Usage: \n\t";
    cout << "./sniffer [-i interface] [-t type] [-c count] [--sip address] [--dip address] [--sport port] [--dprot port] "
         << "\n\n";
    cout << "Optional parameters:\n\t";
    cout << "-i\t\t(number)to capture data interface\n\t";
    cout << "-t\t\tprotocol type(tcp/udp/icmp)\n\t";
    cout << "-c\t\tthe number of captured packets\n\t";
    cout << "--sip\t\tsource ip address\n\t";
    cout << "--dip\t\tdestination ip address\n\t";
    cout << "--sport\t\tsource port(0-65535)\n\t";
    cout << "--dport\t\tdestination port(0-65535)\n\t";
    cout << "--intera\tinteractive mode\n\t";
    cout << "--sendtcp\tSend fake TCP packet\n\t";
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

    if (argc == 2)
    {
        try
        {
            switch (options.at(argv[1]))
            {
            case 7:
                interface(funptr);
                exit(0);
                break;
            case 8:
                SendTcp();
                exit(0);
                break;
            case 9:
                EchoHelp();
                exit(0);
                break;
            default:
                return false;
            }
        }
        catch (std::out_of_range &err)
        {
            return false;
        }
    }

    for (int i = 1; i < argc - 1; i++)
    {
        if ((argv[i][0] == '-') && (argv[i + 1][0] == '-'))
            return false;
    }

    for (int i = 1; i < argc; i++)
    {
        try
        {
            switch (options.at(argv[i]))
            {
            // 网卡必选项
            case 0:
                devflag = true;
                if (++i >= argc)
                    return false;
                devname = argv[i];
                continue;
            case 1:
                if (++i >= argc)
                    return false;
                try
                {
                    count = stoi(argv[i]);
                }
                catch (...)
                {
                    return false;
                }
                continue;
            case 2:
                if (++i >= argc)
                    return false;
                bpfexpr += " && ";
                bpfexpr += argv[i];
                continue;
            case 3:
                if (++i >= argc)
                    return false;
                bpfexpr += " && src host ";
                bpfexpr += argv[i];
                continue;
            case 4:
                if (++i >= argc)
                    return false;
                bpfexpr += " && dst host ";
                bpfexpr += argv[i];
                continue;
            case 5:
                if (++i >= argc)
                    return false;
                bpfexpr += " && src port ";
                bpfexpr += argv[i];
                continue;
            case 6:
                if (++i >= argc)
                    return false;
                bpfexpr += " && dst port ";
                bpfexpr += argv[i];
                continue;
            case 7:
            case 8:
            case 9:
                return false;
            }
        }
        catch (const out_of_range &orr)
        {
            return false;
        }
    }

    if (devflag == false)
        return false;

    bpfexpr.erase(0, 4);

    return true;
}
