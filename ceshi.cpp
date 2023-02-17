#include <iostream>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>

using namespace std;

class PacketHandler{
    public:
        // 构造/析构 - 默认
        PacketHandler() = default;
        ~PacketHandler() = default;

        // 根据数据包地址分析出ip/tcp等包头地址
        void init(const u_char *);

        // 打印ethdr
        void showEthdr();
        void showIp();
        void showItu();

    private:
        struct ether_header *ethdr;
        struct ip *iphdr;
        union{
            struct icmp *icmphdr;
            struct tcphdr *tcphdr;
            struct udphdr *udphdr;
        };
        
        // 拷贝/拷贝赋值 - 删除
        PacketHandler(PacketHandler&) = delete;
        PacketHandler& operator =(PacketHandler &) = delete;
};

void PacketHandler::showIp(void)
{
    cout << "IP包头部信息：\n\t";
    cout << "版本号: " << iphdr->ip_v << "\n\t";
    cout << "源地址: " << inet_ntoa(iphdr->ip_src) << "\n\t";
    cout << "目地址: " << inet_ntoa(iphdr->ip_dst) << "\n\t";
    cout << "上层协议类型: ";
    switch(iphdr->ip_p)
    {
        case 1:
            cout << "ICMP\n\t"; break;
        case 6:
            cout << "TCP\n\t"; break;
        case 17:
            cout << "UDP\n\t"; break;
        default:
            cout << "(OTHER)\n\t"; break;
    }
    cout << "生存时间: " << signed(iphdr->ip_ttl) << "\n";
}

void PacketHandler::showEthdr(void)
{   
    cout << "Ethernet_II帧头部信息:\n\t";
    cout << "源MAC地址: " << ether_ntoa(reinterpret_cast<struct ether_addr *>(ethdr->ether_shost)) << "\n\t";
    cout << "目的MAC地址: " << ether_ntoa(reinterpret_cast<struct ether_addr *>(ethdr->ether_shost)) << "\n\t";
    cout << "上层协议类型: " << hex << (ntohs(ethdr->ether_type) == static_cast<uint16_t>(0x0800) ? "IPv4(0x0800)" : "ARP(0x0806)") << "\n";
}

void PacketHandler::init(const u_char *packet)
{
    // 以太网帧
    ethdr = reinterpret_cast<struct ether_header*>(const_cast<u_char *>(packet));
    // IP包
    iphdr = reinterpret_cast<struct ip*>(const_cast<u_char *>(packet) +14);
    // TCP/UDP/ICMP包
    switch(iphdr->ip_p)
    {
        case 1:
            icmphdr = reinterpret_cast<struct icmp*>(const_cast<u_char *>(packet) + 14 + (iphdr->ip_hl * 4));
            break;
        case 6:
            tcphdr = reinterpret_cast<struct tcphdr*>(const_cast<u_char *>(packet) + 14 + (iphdr->ip_hl * 4));
            break;
        case 17:
            udphdr = reinterpret_cast<struct udphdr*>(const_cast<u_char *>(packet) + 14 + (iphdr->ip_hl * 4));
            break;
    }
}


void loopUserfun(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    PacketHandler packhdr;

    packhdr.init(packet);

    packhdr.showEthdr();

    packhdr.showIp();
    cout << "==============================================\n";
    
}

int main(void)
{
    // 设备句柄
    pcap_t *dev;
    char errbuff[PCAP_ERRBUF_SIZE];

    // 打开网路接口
    dev = pcap_open_live("eth0", 65535, 1, 100, errbuff);
    
    if(dev == NULL)
    {
        cerr << errbuff << endl;
        exit(-1);
    }

    // 配置过滤器
    struct bpf_program setFilter = {0};
    //pcap_compile(dev, &setFilter, "dst host 116.62.66.198", 1, 0);
    pcap_setfilter(dev, &setFilter);
    
    // 捕获数据包
    pcap_loop(dev, 10000, loopUserfun, NULL);

    // 关闭网络接口
    pcap_close(dev);

    return 0;
}
