#include <iostream>
#include <sys/time.h>
#include <time.h>
#include "Option.h"
#include "Sniffer.h"
#include "NetCard.h"
#include "PackStructGraph.h"

using namespace std;

// 回调函数
void loopUserfun(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    PacketHandler packhdr;

    pkthdrInfo(header);

    packhdr.init(packet);
    packhdr.showEthdr();
    packhdr.showIpArp();
    packhdr.showItu();

    EchoPacket(header, packet);

    cout << "=======================================================\n";
}

// 捕获函数
void capture(string devname, string bpfexpr, int count)
{
    // 设备句柄
    pcap_t *dev;
    char errbuff[PCAP_ERRBUF_SIZE];

    // 打开网路接口
    dev = pcap_open_live(devname.c_str(), 65535, 1, 200, errbuff);

    if(dev == NULL)
    {
        cerr << errbuff << endl;
        exit(-1);
    }

    // 设置为非阻塞
    pcap_setnonblock(dev, 0, errbuff);

    // 配置过滤器
    struct bpf_program setFilter = {0};
    pcap_compile(dev, &setFilter, bpfexpr.c_str(), 1, 0);
    pcap_setfilter(dev, &setFilter);

    // 捕获数据包
    pcap_loop(dev, count, loopUserfun, NULL);

    // 关闭网络接口
    pcap_close(dev);
}

// 交互函数 - Option.cpp中直接调用
void Interactive(void)
{
    char c;

    // 获取终端大小
    getTerminalSize(terminalRows, terminalCols);
    
    string devname;
    string srcip;
    string dstip;
    int srcport;
    int dstport;
    int count = 1;

    while(c != 'q')
    {
        clearScreen();
        setCursorPosition(1, (terminalCols- 18) / 2);
        cout << "sniffer的交互模式:\n";
        cout << "=======================================================\n";
        cout << "数据包格式:\n";
        echoPacketStructGraph(4);
        cout << "=======================================================\n";
        cout <<  "请输入捕获的接口(必选): ";
        cin >> devname;
        cout << "请输入源IP: ";
        cin >> srcip;
        cout << "请输入目的IP: ";
        cin >> dstip;
        cout << "请输入源端口: ";
        cin >> srcport;
        cout << "请输入目的端口: ";
        cin >> dstport;
        cout << "请输入捕获数据包数量(default=1): ";
        cin >> count;
        cout << "按Ehter键开始捕获";
        cin.clear();
        cin.sync();
        getchar();

        cout << "=======================================================\n";
        EchoDevIp(devname);

        // 设置过滤表达式
        string bpfexpr;
        if(srcip.length() != 0 && srcip != "0")
        {
            bpfexpr += " && src host ";
            bpfexpr += srcip;
        }

        if(dstip.length() != 0 && dstip != "0")
        {
            bpfexpr += " && dst host ";
            bpfexpr += dstip;
        }

        if(srcport != 0)
        {
            bpfexpr += " && src port ";
            bpfexpr += to_string(srcport);
        }

        if(dstport != 0)
        {
            bpfexpr += " && dst port ";
            bpfexpr += to_string(dstport);
        }

        bpfexpr.erase(0, 4);

        capture(devname, bpfexpr, count);

        cout << "捕获完成！按q退出, w继续\n";
        while(1)
        {
            cin.get(c);
            if(c == 'q')
            {
                cout << "正在退出\n";
                exit(0);
            }
            if(c == 'w')
                break;
        }
    }
}


int main(int argc, char *argv[])
{
    // 获取终端大小
    getTerminalSize(terminalRows, terminalCols);

    int count = 0;
    string devname;
    string bpfexpr;

    // 处理命令行参数
    if(!ArgIfLegal(argc, argv, bpfexpr, devname, count))
    {
        cerr << COL(1, 40, 31) << "\nParameter format error !!!" << OFFCOL << "\n\n";
        EchoHelp();
        exit(-1);
    }

    // 打印捕获网卡信息
    EchoDevIp(devname);
    
    // 开始捕获
    capture(devname, bpfexpr, count);
    
    return 0;
}
