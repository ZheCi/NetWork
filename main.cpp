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


int main(int argc, char *argv[])
{
    // 获取终端大小
    getTerminalSize(terminalRows, terminalCols);

    int count = 0;
    string devname;
    string bpfexpr;

    // 处理命令行参数
    if(!ArgIfLegal(argc, argv, devname, bpfexpr, count, loopUserfun))
    {
        cerr << COL(1, 40, 31) << "\nParameter format error !!!" << OFFCOL << "\n\n";
        EchoHelp();
        exit(-1);
    }

    cout << bpfexpr << endl;

    // 打印捕获网卡信息
    EchoDevIp(devname);
    
    // 开始捕获
    capture(devname, bpfexpr, count, loopUserfun);
    
    return 0;
}
