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
    packhdr.tcphdr = reinterpret_cast<struct tcphdr *>(const_cast<u_char *>(packet + 14 + 20));

    struct tcphdr *tcphdr = packhdr.tcphdr;
     
    printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
            (tcphdr->th_flags & TH_URG ? 'U' : '*'),
            (tcphdr->th_flags & TH_ACK ? 'A' : '*'),
            (tcphdr->th_flags & TH_PUSH ? 'P' : '*'),
            (tcphdr->th_flags & TH_RST ? 'R' : '*'),
            (tcphdr->th_flags & TH_SYN ? 'S' : '*'),
            (tcphdr->th_flags & TH_SYN ? 'F' : '*'),
            ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack),
            ntohs(tcphdr->th_win), 4*tcphdr->th_off);
    printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");

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
