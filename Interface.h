#ifndef __INTERFACE_H__
#define __INTERFACE_H__

typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

int menu(void);
int interface(pcap_handler funptr);

#endif
