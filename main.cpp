#include <fstream>
#include <iostream>
#include <filesystem>
#include <sys/time.h>
#include <time.h>
#include "Option.h"
#include "Sniffer.h"
#include "NetCard.h"
#include "PackStructGraph.h"

using namespace std;

// 文件
std::ofstream OutFile;

// 回调函数
void loopUserfun(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    PacketHandler packhdr;

    pkthdrInfo(header);

    packhdr.init(packet);
    packhdr.showEthdr();
    packhdr.showIpArp();
    packhdr.showItu();

    EchoPacket(header, packet);

    packhdr.SensitiveInfo(OutFile);

    cout << "=======================================================\n";
}

int main(int argc, char *argv[])
{
    // 检擦Sensitive.txt文件大小
    std::filesystem::path fp = std::filesystem::current_path();
    fp += "/Sensitive.txt";

    // 判断fp中的路径不存在
    if (!std::filesystem::exists(fp))
        OutFile.open("Sensitive.txt", std::ios::trunc);
    else
    {
        // 文件大小小于10M，则追加模式打开, 否则截断
        if (std::filesystem::file_size(fp) < 1024 * 10)
            OutFile.open("Sensitive.txt", std::ios::app);
        else
            OutFile.open("Sensitive.txt", std::ios::trunc);
    }

    // 获取终端大小
    getTerminalSize(terminalRows, terminalCols);

    int count = 0;
    string devname;
    string bpfexpr;

    // 处理命令行参数
    if (!ArgIfLegal(argc, argv, devname, bpfexpr, count, loopUserfun))
    {
        cerr << COL(1, 40, 31) << "\nParameter format error !!!" << OFFCOL << "\n\n";
        EchoHelp();
        exit(-1);
    }

    // 清理屏幕
    clearScreen();

    // 打印数据包格式图形
    echoPacketStructGraph(1);
    cout << "\n\n";
    cout << "=======================================================\n";
    // 打印捕获网卡信息
    EchoDevIp(devname);

    // 开始捕获
    capture(devname, bpfexpr, count, loopUserfun);

    // 关闭文件, 这有BUG，其他退出点并没有调用Close关闭文件
    OutFile.close();

    return 0;
}
