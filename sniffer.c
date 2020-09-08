#include "sniffer.h"

#define TCP_PACKET 6

#define VALID_PACKET 1
#define INVALID_PACKET 0

#define MAX_BUFF_SIZE 65536

#define INCOMING_PACKET 1
#define OUTCOMING_PACKET 0

#define LOOPBACK "127.0.0.1"

static void process_packet(unsigned char *packet, size_t packetLen);
static void process_tcp_packet(unsigned char const *packet, size_t packetLen);
static int is_incoming_packet(struct sockaddr_in const *source, 
    struct sockaddr_in const *dest, struct tcphdr const *tcph);
static int is_valid_packet(struct iphdr const *iph, unsigned char const *packet,
    unsigned int *resultProto);
static int get_interface_ip(char *interfaceName, char *resultBuf, size_t bufSize);

static void read_packets_log(char const *filename);

static void write_data_to_logfile(char *filename, struct sockaddr_in const *source,
    struct sockaddr_in const *dest, struct tcphdr const *tcph, size_t ipHdrLen, 
    unsigned char const *packet, size_t packetLen);
static void write_hex_data(FILE *stream, unsigned char const *buf, size_t bufSize);
static void ascii_str_to_hex(unsigned char *output, unsigned char const *input, size_t bufSize);

static unsigned short sniffPort = 0;
static char interfaceName[INTERFACE_NAME_LEN] = { 0, };
static char ipAddrStr[IP_ADDR_STR_LEN] = { 0, };

int snf_start_sniff(char const *interfaceNameStr, unsigned short listenPort)
{
    sniffPort = listenPort;
    strcpy(interfaceName, interfaceNameStr);
    get_interface_ip(interfaceName, ipAddrStr, IP_ADDR_STR_LEN);

    int sock = 0;
    unsigned char *buff = (unsigned char *) malloc(MAX_BUFF_SIZE);
    if ((sock=socket(AF_PACKET, SOCK_RAW,htons(ETH_P_ALL))) < 0) 
    {
        perror("Invalid socket initialize");
        free(buff);
        return INVALID_SOCKET_INIT;
    }

    struct ifreq ethreq;
    strncpy(ethreq.ifr_name, interfaceName, IFNAMSIZ);

	if (ioctl(sock, SIOCGIFFLAGS, &ethreq) == -1) 
	{
		perror("Set promiscuos mode fail");
		close(sock);
        free(buff);
		return INVALID_PROMISC;
	}

	ethreq.ifr_flags |= IFF_PROMISC;

	if (ioctl(sock, SIOCSIFFLAGS, &ethreq) == -1) 
	{
		perror("Set promiscuos mode fail");
		close(sock);
        free(buff);
		return INVALID_PROMISC;
	}

    int numBytes = 0;
    while (1) 
	{
		numBytes = recvfrom(sock, buff, MAX_BUFF_SIZE, 0, NULL, NULL);
		if(numBytes < 0)
		{
			printf("Recvfrom errors, failed to get packets\n");
			continue;
		}
		process_packet(buff, numBytes);
	}
    free(buff);

    ethreq.ifr_flags ^= IFF_PROMISC;
	ioctl(sock, SIOCSIFFLAGS, &ethreq); 
	close(sock);

    return SUCCESSFULL;
}

void snf_read_logs()
{
    int choose = 0;
    while(1)
    {
        printf("1) Read incoming logs.\n");
        printf("2) Read outcoming logs.\n");
        printf("3) Exit\n");
        printf("Enrer command: ");
        scanf("%u", &choose);

        switch(choose)
        {
        case 1:
            read_packets_log("incoming_logs.txt");
            break;
        case 2:
            read_packets_log("outcoming_logs.txt");
            break;
        case 3:
            printf("Exit from program\n");
            exit(1);
            break;
        default:
            printf("Incorrect command\n");
            break;
        }

        while(getchar() != '\n');
    }
    
}

int get_interface_ip(char *interfaceName, char *resultBuf, size_t bufSize)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);

    char *addrString = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    if(strlen(addrString) > bufSize)
    {
        return LITTLE_BUF_SIZE;
    }

    strcpy(resultBuf, addrString);
    return SUCCESSFULL;
}

void process_packet(unsigned char *packet, size_t packetLen)
{
    struct iphdr *iph = (struct iphdr *)(packet  + sizeof(struct ethhdr));
    unsigned int protocol = 0;
    if(!is_valid_packet(iph, packet, &protocol))
    {
        return;
    }
    else
    {
        if(protocol == TCP_PACKET)
        {
            unsigned short iphdrLen;
            iphdrLen = iph->ihl * 4;
            struct tcphdr *tcph=(struct tcphdr*)(packet + sizeof(struct iphdr) + sizeof(struct ethhdr));
            

            struct sockaddr_in source;
            struct sockaddr_in dest;

            memset(&source, 0, sizeof(struct sockaddr_in));
            memset(&dest, 0, sizeof(struct sockaddr_in));

            source.sin_addr.s_addr = iph->saddr;
            dest.sin_addr.s_addr = iph->daddr;

            char filename[25] = {0, };

            if(is_incoming_packet(&source, &dest, tcph))
            {
                strcpy(filename, "incoming_logs.txt");
            }
            else
            {
                strcpy(filename, "outcoming_logs.txt");
            }

            write_data_to_logfile(filename, &source, &dest, tcph, iphdrLen, 
                packet, packetLen);
        }
    }
}

void write_data_to_logfile(char *filename, struct sockaddr_in const *source,
    struct sockaddr_in const *dest, struct tcphdr const *tcph, size_t ipHdrLen, 
    unsigned char const *packet, size_t packetLen)
{
    FILE *stream = fopen(filename, "a+");

    fprintf(stream, "TCP PACKET:\n");
    fprintf(stream, "Source addr: %s | Destination addr: %s\n",
        inet_ntoa(source->sin_addr), inet_ntoa(dest->sin_addr));
    fprintf(stream, "Source port: %u | Destination port: %u\n",
        ntohs(tcph->source), ntohs(tcph->dest));

    size_t dataPacketSize = packetLen - sizeof(struct ethhdr) - 
        ipHdrLen - sizeof(struct tcphdr);

    unsigned char const *dataPtr = packet + sizeof(struct ethhdr) + 
        ipHdrLen + sizeof(struct tcphdr);

    write_hex_data(stream, dataPtr, dataPacketSize);

    fclose(stream);

}

int is_incoming_packet(struct sockaddr_in const *source, 
    struct sockaddr_in const *dest, struct tcphdr const *tcph)
{
    if(!strcmp(inet_ntoa(dest->sin_addr), LOOPBACK))
    {
        if(ntohs(tcph->dest) == sniffPort)
        {
            return INCOMING_PACKET;
        }
        else
        {
            return OUTCOMING_PACKET;
        }
    }
    else if(!strcmp(inet_ntoa(dest->sin_addr), ipAddrStr))
    {
        return INCOMING_PACKET;
    }
    else
    {
        return OUTCOMING_PACKET;
    }

    return INCOMING_PACKET;
}

int is_valid_packet(struct iphdr const *iph, unsigned char const *packet, 
    unsigned int *resultProto)
{
    *resultProto = (unsigned int)iph->protocol;
    if(*resultProto != TCP_PACKET)
    {
        return INVALID_PACKET;
    }
    else
    {
        if(*resultProto == TCP_PACKET)
        {
            unsigned short iphdrlen = iph->ihl * 4;
            struct tcphdr *tcph = (struct tcphdr*)(packet + iphdrlen + sizeof(struct ethhdr));

            unsigned short sourcePort = ntohs(tcph->source);
            unsigned short destPort = ntohs(tcph->dest);

            if(sourcePort == sniffPort || destPort == sniffPort)
            {
                return VALID_PACKET;
            }
            else
            {
                return INVALID_PACKET;
            }
        }
    }
}

void read_packets_log(char const *filename)
{
    size_t readBytes = 0;
    unsigned char buf[512] = {0, };

    FILE *stream = fopen(filename, "r");
    while((readBytes = fread(buf, sizeof(unsigned char), 511, stream)) >= 511)
    {
        printf("%s", buf);
        memset(buf, 0, 512);
    }
    printf("%s", buf);

    fclose(stream);
}

void write_hex_data(FILE *stream, unsigned char const *buf, size_t bufSize)
{
    fprintf(stream, "Raw data:\n");

    unsigned char *hexBuf = (unsigned char*)malloc(bufSize * 2 + 1);
    memset(hexBuf, 0, sizeof(hexBuf));
    
    ascii_str_to_hex(hexBuf, buf, bufSize);

    fwrite(hexBuf, sizeof(unsigned char), bufSize * 2, stream);
    fputc('\n', stream);

    free(hexBuf);
}

void ascii_str_to_hex(unsigned char *output, unsigned char const *input, size_t bufSize)
{
    int offset = 0;
    int i = 0;
    while(i < bufSize)
    {
        sprintf((char*)(output + offset), "%02X", input[i]);
        i++;
        offset += 2;
    }
}