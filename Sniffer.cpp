#include "Sniffer.h"
#include "NetCard.h"

using namespace std;

// 敏感端口
int8_t SensitiveFlag = 0;
const int SensitivePort[] = {22112, 22, 21, 23, 389, 873, 1080, 1352, 1433, 3389, 3306, 6082};

// 打印敏感信息
void PacketHandler::SensitiveInfo(std::ofstream &OutFile)
{
    if (!SensitiveFlag)
        return;
    cout << COL(5, 40, 33) << "敏感信息提醒:" << OFFCOL << "\n\t";
    switch (SensitiveFlag)
    {
    case 1:
        cout << COL(1, 37, 41) << "该链接访问主机的敏感端口\a" << OFFCOL << endl;
    }

    OutFile << getDateTimeString() << "\t";
    OutFile << inet_ntoa(iphdr->ip_src) << ":";
    if (iphdr->ip_p == 17)
        OutFile << ntohs(udphdr->uh_sport);
    else if (iphdr->ip_p == 6)
        OutFile << ntohs(tcphdr->th_sport);
    OutFile << " ————————> ";
    OutFile << inet_ntoa(iphdr->ip_dst) << ":";
    if (iphdr->ip_p == 17)
        OutFile << ntohs(udphdr->uh_dport);
    else if (iphdr->ip_p == 6)
        OutFile << ntohs(tcphdr->th_dport);
    OutFile << endl;
    SensitiveFlag = 0;
}

// 捕获函数
void capture(string devname, string bpfexpr, int count, pcap_handler funptr)
{
    // 设备句柄
    pcap_t *dev;
    char errbuff[PCAP_ERRBUF_SIZE];

    // 打开网路接口
    dev = pcap_open_live(devname.c_str(), 65535, 1, 200, errbuff);

    if (dev == NULL)
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
    pcap_loop(dev, count, funptr, NULL);

    // 关闭网络接口
    pcap_close(dev);
}

// 打印传输层
void PacketHandler::showItu(void)
{
    if (ntohs(ethdr->ether_type) == static_cast<uint16_t>(0x0806))
        return;
    switch (iphdr->ip_p)
    {
    case 1:
        showIcmp();
        break;
    case 6:
        showTcp();
        break;
    case 17:
        showUdp();
        break;
    }
}

// 打印ICMP数据包
void PacketHandler::showIcmp(void)
{
    cout << COL(5, 40, 33) << "ICMP头部信息:" << OFFCOL << "\n\t";

    printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->icmp_type, icmphdr->icmp_code, ntohs(icmphdr->icmp_hun.ih_idseq.icd_id), ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq));
}

// 打印UDP数据包
void PacketHandler::showUdp(void)
{
    // 敏感端口检测
    for (auto i : SensitivePort)
        if (i == ntohs(tcphdr->th_dport))
            SensitiveFlag |= 0x1;

    cout << COL(5, 40, 33) << "UDP头部信息:" << OFFCOL << "\n\t";
    cout << "源端口: " << dec << ntohs(udphdr->uh_sport) << "\n\t";
    cout << "目的端口: " << dec << ntohs(udphdr->uh_dport) << "\n\t";
    cout << "长度: " << dec << ntohs(udphdr->uh_ulen) << "\n\t";
    cout << "校验和: " << dec << ntohs(udphdr->uh_sum) << "\n";
}

// 打印TCP数据包
void PacketHandler::showTcp(void)
{
    // 敏感端口检测
    for (auto i : SensitivePort)
        if (i == ntohs(tcphdr->th_dport))
            SensitiveFlag |= 0x1;

    cout << COL(5, 40, 33) << "TCP头部信息:" << OFFCOL << "\n\t";
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
           ntohs(tcphdr->th_win), 4 * tcphdr->th_off);
}

// 打印网络层
void PacketHandler::showIpArp(void)
{
    ntohs(ethdr->ether_type) == static_cast<uint16_t>(0x0800) ? (showIp()) : (showArp());
}

// 打印ARP数据包
void PacketHandler::showArp(void)
{
    cout << COL(5, 40, 34) << "(R)ARP头部信息:" << OFFCOL << "\n\t";
    cout << "硬件类型: " << (ntohs(arphdr->ea_hdr.ar_hrd) == 0x0001 ? "Ether" : "Unknown") << "\n\t";
    cout << "协议类型: " << (ntohs(arphdr->ea_hdr.ar_pro) == 0x800 ? "IPv4" : "Unknown") << "\n\t";
    cout << "操作码: ";

    switch (ntohs(arphdr->ea_hdr.ar_op))
    {
    case ARPOP_REQUEST:
        cout << "ARPOP_REQUEST(ARP请求)\n\t";
        break;
    case ARPOP_REPLY:
        cout << "ARPOP_REPLY(ARP应答)\n\t";
        break;
    case ARPOP_RREQUEST:
        cout << "ARPOP_RREQUEST(RARP请求)\n\t";
        break;
    case ARPOP_RREPLY:
        cout << "ARPOP_RREPLY(RARP应答)\n\t";
        break;
    case ARPOP_InREQUEST:
        cout << "ARPOP_InREQUEST(在ARP请求中)\n\t";
        break;
    case ARPOP_InREPLY:
        cout << "ARPOP_InREPLY(在ARP应答中)\n\t";
        break;
    case ARPOP_NAK:
        cout << "ARPOP_NAK((ATM)ARP否定)\n\t";
        break;
    default:
        cout << "Unknown\n\t";
        break;
    }

    cout << "源IP地址: ";
    for (int i = 0; i < 4; i++)
    {
        if (i == 3)
        {
            cout << dec << static_cast<unsigned>(arphdr->arp_spa[i]) << "\t";
            break;
        }
        cout << dec << static_cast<unsigned>(arphdr->arp_spa[i]) << '.';
    }
    cout << "源MAC地址: " << ether_ntoa(reinterpret_cast<struct ether_addr *>(arphdr->arp_sha)) << "\n\t";

    cout << "目的IP地址: ";
    for (int i = 0; i < 4; i++)
    {
        if (i == 3)
        {
            cout << dec << static_cast<unsigned int>(arphdr->arp_tpa[i]) << "\t";
            break;
        }
        cout << dec << static_cast<unsigned>(arphdr->arp_tpa[i]) << ".";
    }
    cout << "目的MAC地址: " << ether_ntoa(reinterpret_cast<struct ether_addr *>(arphdr->arp_tha)) << "\n";
}

// 打印IP数据包
void PacketHandler::showIp(void)
{
    cout << COL(5, 40, 34) << "IP包头部信息:" << OFFCOL << "\n\t";
    cout << "版本号: " << iphdr->ip_v << "\n\t";
    cout << "源地址: " << inet_ntoa(iphdr->ip_src) << "\n\t";
    cout << "目地址: " << inet_ntoa(iphdr->ip_dst) << "\n\t";
    cout << "上层协议类型: ";
    switch (iphdr->ip_p)
    {
    case 1:
        cout << "ICMP\n\t";
        break;
    case 6:
        cout << "TCP\n\t";
        break;
    case 17:
        cout << "UDP\n\t";
        break;
    default:
        cout << "(OTHER)\n\t";
        break;
    }
    cout << "生存时间: " << signed(iphdr->ip_ttl) << "\n";
}

// 但因数据链路层，以太网帧
void PacketHandler::showEthdr(void)
{
    cout << COL(5, 40, 32) << "Ethernet_II帧头部信息:" << OFFCOL << "\n\t";

    cout << "源MAC地址: " << ether_ntoa(reinterpret_cast<struct ether_addr *>(ethdr->ether_shost)) << "\n\t";
    cout << "目的MAC地址: " << ether_ntoa(reinterpret_cast<struct ether_addr *>(ethdr->ether_shost)) << "\n\t";
    cout << "上层协议类型: " << hex << (ntohs(ethdr->ether_type) == static_cast<uint16_t>(0x0800) ? "IPv4(0x0800)" : "ARP(0x0806)") << "\n";
}

// 数据包头部初始化
void PacketHandler::init(const u_char *packet)
{
    // 以太网帧
    ethdr = reinterpret_cast<struct ether_header *>(const_cast<u_char *>(packet));

    // ARP包
    if (ntohs(ethdr->ether_type) == static_cast<uint16_t>(0x0806))
    {
        arphdr = reinterpret_cast<struct ether_arp *>(const_cast<u_char *>(packet) + 14);
        return;
    }

    // IP包
    iphdr = reinterpret_cast<struct ip *>(const_cast<u_char *>(packet) + 14);

    // TCP/UDP/ICMP包
    switch (iphdr->ip_p)
    {
    case 1:
        icmphdr = reinterpret_cast<struct icmp *>(const_cast<u_char *>(packet) + 14 + (iphdr->ip_hl * 4));
        break;
    case 6:
        tcphdr = reinterpret_cast<struct tcphdr *>(const_cast<u_char *>(packet) + 14 + (iphdr->ip_hl * 4));
        break;
    case 17:
        udphdr = reinterpret_cast<struct udphdr *>(const_cast<u_char *>(packet) + 14 + (iphdr->ip_hl * 4));
        break;
    }
}

// 数据包整体基本信息
void pkthdrInfo(const struct pcap_pkthdr *header)
{
    char buffer[80];
    struct tm *tm_ptr;

    tm_ptr = localtime(&(header->ts.tv_sec));

    strftime(buffer, 80, "%Y/%m/%d %H:%M:%S ", tm_ptr);

    unsigned int ms = (header->ts.tv_usec) / 1000;
    unsigned int ws = (header->ts.tv_usec) % 1000;

    string tim = buffer;

    tim = tim + to_string(ms) + "." + to_string(ws) + "ms";

    cout << COL(5, 40, 31) << "数据包信息摘要:" << OFFCOL << "\n\t";
    cout << "捕获时间: " << tim << "\n\t";
    cout << "捕获数据包的长度: " << header->caplen << "\n\t";
    cout << "数据包的实际长度: " << header->len << "\n";
}

// 打印数据包内容
void EchoPacket(const struct pcap_pkthdr *header, const u_char *packet)
{
    cout << COL(5, 40, 37) << "数据包内容:" << OFFCOL << "\n\t";
    for (int i = 0; i < static_cast<int>(header->len); i++)
    {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0)
            printf("\n\t");
        if ((i == 90))
        {
            cout << "......";
            break;
        }
    }
    printf("\n\n");
}
