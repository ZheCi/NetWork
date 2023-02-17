#include <iostream>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>

using namespace std;

class PacketHandler{
    public:
        string showInfoIP(void) { return iphdrInfo; };
        string showInfoITU(void) { return ituhdrInfo; };

        struct ether_header *ethdr;
        struct ip *iphdr;
        union{
            struct icmp *icmphdr;
            struct tcphdr *tcphdr;
            struct udphdr *udphdr;
        };

        string ethdrInfo;
        string iphdrInfo;
        string ituhdrInfo;
    private:
};

void loopUserfun(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    // 包头部
    PacketHandler packhdr;

    packhdr.ethdr = reinterpret_cast<struct ether_header *>(const_cast<u_char *>(packet));

     cout << "源MAC地址: " << ether_ntoa(reinterpret_cast<struct ether_addr *>(packhdr.ethdr->ether_shost)) << endl;
     cout << "目的MAC地址: " << ether_ntoa(reinterpret_cast<struct ether_addr *>(packhdr.ethdr->ether_dhost)) << endl;
     cout << "类型: " << (ntohs(packhdr.ethdr->ether_type) == static_cast<uint16_t>(0x800) ? "IPv4(0x0800)" : "ARP(0x0806)") << endl;
    
    // 确定Ip包头位置，14是以太网头部长度
    packhdr.iphdr = (reinterpret_cast<struct ip*>(const_cast<u_char *>(packet) +14));
    //if((packhdr.iphdr)->ip_p == 6)
    {
        cout <<  "IP版本号: " << (packhdr.iphdr)->ip_v << endl;
        cout << "IP头部长度: " << (packhdr.iphdr)->ip_hl * 4<< endl;    
        cout << "生存时间: " <<  (packhdr.iphdr)->ip_ttl << endl;
        switch((packhdr.iphdr)->ip_p)
        {
            case 1:
                cout << "ICMP\n";
                break;
            case 6:
                cout << "TCP\n";
                packhdr.tcphdr = reinterpret_cast<struct tcphdr *>(const_cast<u_char *>(packet + 14 + 20));
                cout << "源端口: " << ntohs(packhdr.tcphdr->th_sport)<< endl;
                cout << "目的端口: " << ntohs(packhdr.tcphdr->th_dport)<< endl;
                break;
            case 17:
                cout << "UDP\n";
                break;
            default:
                cout << "OTHER\n";
                break;
        }

        cout << "src: " << inet_ntoa((packhdr.iphdr)->ip_src) << endl;
        cout << "dst: " << inet_ntoa((packhdr.iphdr)->ip_dst) << endl;
        cout << endl;
        
    }
}

int main(void)
{
    // 设备句柄
    pcap_t *dev;

    char errbuff[PCAP_ERRBUF_SIZE];

    // 打开网络接口
    dev = pcap_open_live("eth0", 65535, 1, 1000, errbuff);

    if(dev == NULL)
    {
        cerr << errbuff << endl;
        exit(-1);
    }
    // 配置过滤器
    struct bpf_program setFilter = {0};
    //pcap_compile(dev, &setFilter, "dest port 8989", 1, 0);
    pcap_setfilter(dev, &setFilter);
    
    // 捕获数据包
    pcap_loop(dev, -1, loopUserfun, NULL);

    pcap_close(dev);

    return 0;
}
