#include <iostream>
#include <sys/time.h>
#include <time.h>
#include "Option.h"
#include "Sniffer.h"
#include "NetCard.h"

using namespace std;

void loopUserfun(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    
    PacketHandler packhdr;

    pkthdrInfo(header);

    packhdr.init(packet);
    packhdr.showEthdr();
    packhdr.showIpArp();
    packhdr.showItu();

    EchoPacket(header, packet);

    cout << "================================================================\n";

}

int main(int argc, char *argv[])
{
    unsigned int count = 0;
    string devname;
    string bpfexpr;

    if(!ArgIfLegal(argc, argv, bpfexpr, devname, count))
    {
        cout << COL(1, 40, 31) << "\nParameter format error !!!" << OFFCOL << "\n\n";
        EchoHelp();
        exit(-1);
    }


    EchoDevIp(devname);
    
    // 设备句柄
    pcap_t *dev;
    char errbuff[PCAP_ERRBUF_SIZE];

    // 打开网路接口
    dev = pcap_open_live(devname.c_str(), 65535, 1, 1000, errbuff);

    if(dev == NULL)
    {
        cerr << errbuff << endl;
        exit(-1);
    }

    // 设置为非阻塞
    pcap_setnonblock(dev, 1, errbuff);

    // 配置过滤器
    struct bpf_program setFilter = {0};
    pcap_compile(dev, &setFilter, bpfexpr.c_str(), 1, 0);
    pcap_setfilter(dev, &setFilter);

    // 捕获数据包
    //pcap_dispatch(dev, 100, loopUserfun, NULL);
    pcap_loop(dev, count, loopUserfun, NULL);

    // 关闭网络接口
    pcap_close(dev);

    return 0;
}
