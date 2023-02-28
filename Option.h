#ifndef __OPTION_H__
#define __OPTION_H__

#include "NetCard.h"

typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

// 打印帮助信息
void EchoHelp(void);
// 获取用户输入的参数值
bool ArgIfLegal(int argc, char *argv[], string &bpfexpr, string &devname, int &count, pcap_handler funptr);

// 交互函数
extern void Interactive(void);

#endif
