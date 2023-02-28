#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include "NetCard.h"

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

typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

// 开始捕获函数
void capture(string devname, string bpfexpr, int count, pcap_handler funptr);

// 打印数据包信息概述
void pkthdrInfo(const struct pcap_pkthdr *header);
// 打印数据包内容
void EchoPacket(const struct pcap_pkthdr *header, const u_char *packet);

#endif
