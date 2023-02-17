#include <set>
#include <arpa/inet.h>
#include <iostream>
#include <bitset>
#include <vector>
#include <pcap.h>
#include <set>
#include <map>

using namespace std;

class NetCardInfo
{
    friend bool GetNetCardList(NetCardInfo &);

    public:
        // 返回指定接口的IP
        set<pair<string, string>> searchName(string name){ return name_ip[name]; }
        
    private:
        map<string, set<pair<string, string>>> name_ip;

        // 插入
        void insert(pair<string, set<pair<string, string>>> net){ name_ip.insert(net); }
};

bool GetNetCardList(NetCardInfo &netcard)
{
    pcap_if_t *allDevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取设备(网卡)列表
    if(pcap_findalldevs(&allDevs, errbuf) == -1)
    {
        cerr << "Error in pcap_findalldevs_ex:" << errbuf << endl;
        return false;
    }

    // 遍历设备(网卡)列表
    for(pcap_if_t *tem = allDevs; tem != NULL; tem = tem->next)
    {
        const string name = tem->name;
        
        // 存储当前处理接口的所有IP信息
        set<pair<string, string>> adds;

        // 遍历设备(网卡)的所有IP
        for(struct pcap_addr *ip = tem->addresses; ip != NULL; ip = ip->next )
        {
            pair<string, string> ipadd;
            // 判断 IP 协议簇是否为 AF_INET(ipv4)
            if(ip->addr->sa_family == AF_INET)
            {
                // ip 
                ipadd.first = inet_ntoa(reinterpret_cast<struct sockaddr_in*>(ip->addr)->sin_addr);
                // 掩码
                ipadd.second = inet_ntoa(reinterpret_cast<struct sockaddr_in*>(ip->netmask)->sin_addr);
                
                adds.insert(ipadd);
            }
        }
        
        // 存储当前处理设置(网卡)的信息, 设备名-地址列表
        netcard.insert(pair<string, set<pair<string, string>>>(name, adds));
    }

    // 所有设备信息获取完成，释放设备(网卡)列表
    pcap_freealldevs(allDevs);

    return true;
}

int main(void)
{
    NetCardInfo netDev;
    GetNetCardList(netDev);
    
    set<pair<string, string>> eth = netDev.searchName("lo");

    for (auto i : eth)
    {
        cout << i.first << endl;
        cout << i.second<< endl;
    }
    
    return 0;
}
