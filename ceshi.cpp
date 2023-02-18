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
        void showItu();
        void showIpArp();

    private:
        // Ehter
        struct ether_header *ethdr;
        // (IP  and TCP/UCP/ICMP) or ARP
        union{
            //IP and TCP/UDP/ICMP
            struct{
                //IP
                struct ip *iphdr;
                //TCP/UDP/ICMP
                union{
                    struct icmp *icmphdr;
                    struct tcphdr *tcphdr;
                    struct udphdr *udphdr;
                };
            };
            // ARP
            struct ether_arp *arphdr;
        }; 

        // 为shwoIpArp中的回调函数，用户不能直接调用
        void showIp();
        void showArp();

        // 为showItu中的回调函数，用户不能直接访问
        void showTcp();
        void showUdp();
        void showIcmp();

        // 拷贝/拷贝赋值 - 删除
        PacketHandler(PacketHandler&) = delete;
        PacketHandler& operator =(PacketHandler &) = delete;
};

void PacketHandler::showItu(void)
{
    if(ntohs(ethdr->ether_type) == static_cast<uint16_t>(0x0806))
        return;
    switch(iphdr->ip_p) 
    {
        case 1:
            showIcmp(); break;
        case 6:
            showTcp(); break;
        case 17:
            showUdp(); break;
    }
}

void PacketHandler::showIcmp(void)
{
    cout << "ICMP头部信息: \n\t";
    printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->icmp_type, icmphdr->icmp_code, ntohs(icmphdr->icmp_hun.ih_idseq.icd_id), ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq));
}

void PacketHandler::showUdp(void)
{
    cout << "UDP头部信息: \n\t";
    cout << "源端口: " << dec << ntohs(udphdr->uh_sport) << "\n\t";
    cout << "目的端口: " << dec << ntohs(udphdr->uh_dport) << "\n\t";
    cout << "长度: " << dec << ntohs(udphdr->uh_ulen) << "\n\t";
    cout << "校验和: " << dec << ntohs(udphdr->uh_sum) << "\n";
}

void PacketHandler::showTcp(void)
{
    cout << "TCP头部信息: \n\t";
    cout << "源端口: " << dec << ntohs(tcphdr->th_sport) << "\n\t";
    cout << "目的端口: " << dec << ntohs(tcphdr->th_dport) << "\n\t";

    printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
            (tcphdr->th_flags & TH_URG ? 'U' : '*'),
            (tcphdr->th_flags & TH_ACK ? 'A' : '*'),
            (tcphdr->th_flags & TH_PUSH ? 'P' : '*'),
            (tcphdr->th_flags & TH_RST ? 'R' : '*'),
            (tcphdr->th_flags & TH_SYN ? 'S' : '*'),
            (tcphdr->th_flags & TH_FIN ? 'F' : '*'),
            ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack),
            ntohs(tcphdr->th_win), 4*tcphdr->th_off);
}

void PacketHandler::showIpArp(void)
{
    ntohs(ethdr->ether_type) == static_cast<uint16_t>(0x0800) ? (showIp()) : (showArp()); 

}

void PacketHandler::showArp(void)
{
    cout << "(R)ARP头部信息: \n\t";
    cout << "硬件类型: " << (ntohs(arphdr->ea_hdr.ar_hrd) == 0x0001 ? "Ether" : "Unknown") << "\n\t";
    cout << "协议类型: " << (ntohs(arphdr->ea_hdr.ar_pro) == 0x800 ? "IPv4" : "Unknown") << "\n\t";
    cout << "操作码: ";

    switch(ntohs(arphdr->ea_hdr.ar_op))
    {
        case ARPOP_REQUEST:
            cout << "ARPOP_REQUEST(ARP请求)\n\t"; break;
        case ARPOP_REPLY:
            cout << "ARPOP_REPLY(ARP应答)\n\t"; break;
        case ARPOP_RREQUEST:
            cout << "ARPOP_RREQUEST(RARP请求)\n\t"; break;
        case ARPOP_RREPLY:
            cout << "ARPOP_RREPLY(RARP应答)\n\t"; break;
        case ARPOP_InREQUEST:
            cout << "ARPOP_InREQUEST(在ARP请求中)\n\t"; break;
        case ARPOP_InREPLY:
            cout << "ARPOP_InREPLY(在ARP应答中)\n\t"; break;
        case ARPOP_NAK:
            cout << "ARPOP_NAK((ATM)ARP否定)\n\t"; break;
        default: cout << "Unknown\n\t"; break;
    }

    cout << "源IP地址: ";
    for(int i = 0; i < 4; i++)
    {
        if(i == 3)
        {
            cout << dec << static_cast<unsigned>(arphdr->arp_spa[i]) << "\t";
            break;
        }
        cout << dec << static_cast<unsigned>(arphdr->arp_spa[i]) << '.';
    }
    cout << "源MAC地址: " << ether_ntoa(reinterpret_cast<struct ether_addr *>(arphdr->arp_sha)) << "\n\t";

    cout << "目的IP地址: ";
    for(int i = 0; i < 4; i++)
    {
        if(i == 3)
        {
            cout << dec << static_cast<unsigned int>(arphdr->arp_tpa[i]) << "\t";
            break;
        }
        cout << dec << static_cast<unsigned>(arphdr->arp_tpa[i]) << ".";
    }
    cout << "目的MAC地址: " << ether_ntoa(reinterpret_cast<struct ether_addr *>(arphdr->arp_tha)) << "\n";
}

void PacketHandler::showIp(void)
{
    cout << "IP包头部信息: \n\t";
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

    // ARP包
    if(ntohs(ethdr->ether_type)== static_cast<uint16_t>(0x0806))
    {
        arphdr = reinterpret_cast<struct ether_arp*>(const_cast<u_char *>(packet) +14);
        return;
    }

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

    packhdr.showIpArp();

    packhdr.showItu();

    cout << "================================================================\n";

}

int main(void)
{
    // 设备句柄
    pcap_t *dev;
    char errbuff[PCAP_ERRBUF_SIZE];

    // 打开网路接口
    dev = pcap_open_live("eth0", 65535, 1, 1000, errbuff);

    if(dev == NULL)
    {
        cerr << errbuff << endl;
        exit(-1);
    }

    // 配置过滤器
    struct bpf_program setFilter = {0};
    pcap_compile(dev, &setFilter, "udp", 1, 0);
    pcap_setfilter(dev, &setFilter);

    // 捕获数据包
    pcap_loop(dev, 10000, loopUserfun, NULL);

    // 关闭网络接口
    pcap_close(dev);

    return 0;
}
