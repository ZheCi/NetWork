#ifndef __SENDTCP_H__
#define __SENDTCP_H__

#include <iomanip>
#include <limits>
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <algorithm>

class PackInfoUser
{
    public:
        std::string sip;
        std::string dip;
        int sport;
        int dport;
        std::string data;
        uint16_t seq;
        uint16_t seq_ack;
};

int SendTcp(void);

#endif
