// 交互模块

#include <iostream>
#include <limits>
#include "PackStructGraph.h"
#include "Interface.h"
#include "Sniffer.h"
#include "SendTcp.h"

typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

using namespace std;

// 菜单
int menu(void)
{
    int i = 0;
    
    clearScreen();
    cout << "=======================================================\n";
    cout << "\t1、设置捕获网卡接口(必选项)\n"; 
    cout << "\t2、设置捕获次数\n";
    cout << "\t3、设置捕获参数\n";
    cout << "\t4、开始捕获\n";
    cout << "\t5、发送TCP数据报文\n";
    cout << "\t6、退出\n";
    cout << "=======================================================\n";
    cout << setw(41) << setfill(' ') << right << "请输入选择：";
    cin >> i;
    cout << "=======================================================\n";
    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    return i;
}

int interface(pcap_handler funptr)
{
    string devname("");
    string bpfexpr("");
    string tem("");
    int count = 1;

    while(1)
    {
        switch(menu())
        {   
            case 1:
                cout << "请输入要捕获的网络接口: ";
                cin >> devname;
                break;
            case 2:
                cout << "请输入要捕获的次数: ";
                cin >> count;
                break;
            case 3:
                cout << "请输入源IP: ";
                cin >> tem;
                if(tem.size())
                {
                    bpfexpr += " && src host ";
                    bpfexpr += tem;
                }

                cout << "请输入目的IP: ";
                cin >> tem;
                if(tem.size())
                {
                    bpfexpr += " && dst host ";
                    bpfexpr += tem;
                }

                cout << "请输入源端口: ";
                cin >> tem;
                if(tem.size())
                {
                    bpfexpr += " && src port ";
                    bpfexpr += tem;
                }

                cout << "请输入目的端口: ";
                cin >> tem;
                if(tem.size())
                {
                    bpfexpr += " && dst port ";
                    bpfexpr += tem;
                }

                bpfexpr.erase(0, 4);
                break;
            case 4:
                EchoDevIp(devname);
                capture(devname, bpfexpr, count, funptr);
                cout << "捕获完成，按Enter继续\n";
                // 恢复初始状态
                devname = "";
                bpfexpr = "";
                count = 1;
                getchar();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            case 5:
                SendTcp();               
                break;
            case 6:
                return 0;
            default:
                cout << "输入有误，已自动退出\n";
                return 0;
        }
    }

    return 0;
}

