#include <iostream>
#include <map>

using namespace std;

void EchoHelp(void)
{
    cout << "usage: ./sniffer [options] ..." << "\n\n";
    cout << "Optional parameters:\n\t";
    cout << "-i\t\t(number)to capture data interface\n\t";
    cout << "-t\t\tprotocol type(tcp/udp/icmp)\n\t";
    cout << "-c\t\tthe number of captured packets\n\t";
    cout << "--sip\t\tsource ip address\n\t";
    cout << "--dip\t\tdestination ip address\n\t";
    cout << "--sprot\t\tsource port(0-65535)\n\t";
    cout << "--dprot\t\tdestination port(0-65535)\n\t";
    cout << "--help\t\thelp information\n";
}

bool ArgIfLegal(int argc, char *argv[], string &bpfexpr, string &devname, unsigned int &count)
{
    if(argc == 1)
        return false;

    map<string, int> options;

    options.insert(pair<string, int>("-i", 0));
    options.insert(pair<string, int>("-c", 1));
    options.insert(pair<string, int>("-t", 2));
    options.insert(pair<string, int>("--sip", 3));
    options.insert(pair<string, int>("--dip", 4));
    options.insert(pair<string, int>("--sport", 5));
    options.insert(pair<string, int>("--dport", 6));
    options.insert(pair<string, int>("--help", 7));
    
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
                case 7:
                    i++;
                    if(argc != 2)
                        return false;
                    EchoHelp();
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
