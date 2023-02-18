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

