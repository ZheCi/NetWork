#ifndef __NETCARD_H__
#define __NETCARD_H__

#include <iomanip>
#include <ctime>
#include <sstream>
#include <arpa/inet.h>
#include <iostream>
#include <bitset>
#include <vector>
#include <pcap.h>
#include <set>
#include <map>

#define COL(x, y, z) "\033[" #x ";" #y ";" #z "m"
#define OFFCOL "\033[0m"

using namespace std;
using NetAddrList = set<pair<string, string>>;

class NetCardInfo
{
    friend bool GetNetCardList(NetCardInfo &);
    friend void EchoAllDev(void);

public:
    // 返回指定接口的IP
    NetAddrList searchName(const string name);

private:
    map<string, NetAddrList> name_ip;
    void insert(pair<string, NetAddrList> net);
};

// 打印指定网卡信息
void EchoDevIp(const string name);
// 打印所有网卡信息
void EchoAllDev(void);
// 获取网卡列表且保存在参数(netcard)中
bool GetNetCardList(NetCardInfo &netcard);
// 打印时间
std::string getDateTimeString();

#endif
