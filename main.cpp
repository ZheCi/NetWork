#include <iostream>
#include "Sniffer.h"
#include "NetCard.h"

using namespace std;

void loopUserfun(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    PacketHandler packhdr;

    packhdr.init(packet);

    packhdr.showEthdr();

    packhdr.showIpArp();

    packhdr.showItu();

    cout << "================================================================\n";

}

int main(void)
{
    EchoDevIp("eth0");
    
    // 设备句柄
    pcap_t *dev;
    char errbuff[PCAP_ERRBUF_SIZE];

    // 打开网路接口
    dev = pcap_open_live("eth0", 65535, 1, 200, errbuff);

    if(dev == NULL)
    {
        cerr << errbuff << endl;
        exit(-1);
    }

    // 配置过滤器
    struct bpf_program setFilter = {0};
    pcap_compile(dev, &setFilter, "tcp", 1, 0);
    //pcap_setfilter(dev, &setFilter);

    // 捕获数据包
    pcap_loop(dev, 1, loopUserfun, NULL);

    // 关闭网络接口
    pcap_close(dev);

    return 0;
}
