#ifndef SNIFFER_H
#define SNIFFER_H

#include <linux/if_ether.h> 
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define SUCCESSFULL 0
#define LITTLE_BUF_SIZE -1

#define INVALID_PROMISC -1
#define INVALID_SOCKET_INIT -2

#define INTERFACE_NAME_LEN 32
#define IP_ADDR_STR_LEN 16

int snf_start_sniff(char const *interfaceNameStr, unsigned short listenPort);
void snf_read_logs();


#endif // SNIFFER_H