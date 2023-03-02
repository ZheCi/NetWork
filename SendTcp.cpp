#include "SendTcp.h"
#include "PackStructGraph.h"

using namespace std;

int SendTcp(void)
{
    clearScreen();
    
    PackInfoUser dataInfo;

    cout << "========================================================\n";
    cout << "                        构造Tcp报文\n";
    cout << "========================================================\n";
    cout << "源头IP：";
    cin >> dataInfo.sip;
    cout << "目的IP：";
    cin >> dataInfo.dip;
    cout << "源端口：";
    cin >> dataInfo.sport;
    cout << "目的端口：";
    cin >> dataInfo.dport;
    cout << "序列号：";
    cin >> dataInfo.seq;
    cout << "确认号：";
    cin  >> dataInfo.seq_ack;
    cout << "要发送的数据：";
    cin >> dataInfo.data;
    cout << "========================================================\n";

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(dataInfo.sip.c_str());
    dest_addr.sin_port = htons(80);

    const int packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + dataInfo.data.size();

    char* packet = new char[packet_size];
    memset(packet, 0, packet_size);

    struct iphdr* ip = (struct iphdr*)packet;
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->id = htons(1);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr(dataInfo.sip.c_str());
    ip->daddr = inet_addr(dataInfo.dip.c_str());
    ip->tot_len = htons(packet_size);
    ip->check = 0;

    struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
    tcp->source = htons(dataInfo.sport);
    tcp->dest = htons(dataInfo.dport);
    tcp->seq = htonl(dataInfo.seq);
    tcp->ack_seq = htonl(dataInfo.seq_ack);
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(65535);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    memcpy(packet + packet_size - dataInfo.data.size(), dataInfo.data.c_str(), dataInfo.data.size());

    int ret = sendto(sockfd, packet, packet_size, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    if (ret < 0) {
        perror("sendto");
        return -1;
    }

    delete[] packet;

    cout << "数据包发送完成，按Enter继续....\n";
    cout << "========================================================\n";

    close(sockfd);

    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    getchar();
    
    return 0;
}

