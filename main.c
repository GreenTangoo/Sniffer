#include "sniffer.h"

struct ThreadArgs 
{
    char interfaceName[INTERFACE_NAME_LEN];
    unsigned short sniffPort;
};

void sniffing_inner(void *args)
{
    struct ThreadArgs *passArgs = (struct ThreadArgs*)(args);
    snf_start_sniff(passArgs->interfaceName, passArgs->sniffPort);
}

void read_logs_inner()
{
    snf_read_logs();
}

int main(int argc, char **argv)
{
    if(argc != 3)
    {
        printf("Usage: <binary_name> <interface_name> <listen_port>\n");
        return -1;
    }

    struct ThreadArgs args;
    strcpy(args.interfaceName, argv[1]);
    args.sniffPort = atoi(argv[2]);

    pthread_t tid1;
    pthread_t tid2;
    printf("Start sniffing\n");

    pthread_create(&tid1, NULL, sniffing_inner, (void*)&args);
    pthread_create(&tid2, NULL, read_logs_inner, NULL);

    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);

    return 0;
}