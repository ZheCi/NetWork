#include <set>
#include <arpa/inet.h>
#include <iostream>
#include <bitset>
#include <vector>
#include <pcap.h>
#include <set>
#include <map>

using namespace std;
using NetAddrList=set<pair<string, string>>;

class NetCardInfo
{
    friend bool GetNetCardList(NetCardInfo &);

    public:
        // 返回指定接口的IP
        NetAddrList searchName(const string name);
    private:
        map<string, NetAddrList> name_ip;
        void insert(pair<string, NetAddrList> net);
};

// 打印指定网卡信息
void EchoDevIp(const string name);
// 获取网卡列表且保存在参数(netcard)中
bool GetNetCardList(NetCardInfo &netcard);
