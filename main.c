#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;

struct tcp_seg {
    uint16 src_port;
    uint16 dst_port;
    uint32 seq_num;
    uint32 ack_num;
    uint8 offset;
    uint8 res;
    uint8 flag;
    uint16 win;
    uint16 chksum;
    uint16 u_pnt;
    uint32 option[10];

    u_char* tcp_data;
};

struct ip_dtgm {
    uint8 ver;
    uint8 ihl;
    uint8 tos;
    uint16 ttl_len;
    uint16 id;
    uint8 flag;
    uint16 offset;
    uint8 ttl;
    uint8 prtl;
    uint16 chksum;
    uint32 src_addr;
    uint32 dst_addr;
    uint32 option[10];

    struct tcp_seg ip_data;
};

struct eth_frame {
    uint8 dst_mac[6];
    uint8 src_mac[6];
    uint16 eth_type;

    struct ip_dtgm eth_data;
};

uint16 cpy_2(const u_char* src)
{
    uint16 tmp = 0;
    for (int i = 0; i < 2; i++) {
        tmp <<= 8;
        tmp += src[i];
    }
    return tmp;
}

uint32 cpy_4(const u_char* src)
{
    uint32 tmp = 0;
    for (int i = 0; i < 4; i++) {
        tmp <<= 8;
        tmp += src[i];
    }
    return tmp;
}

int ext_http(const u_char* src)
{
    for (int i = 0; i < 16; i++) {
        if (i == 8)
            printf("\n");
        if (src[i] >= 33 && src[i] <= 126)
            printf("%c ", src[i]);
        else
            printf(". ");
    }
    printf("\n");
}

int ext_tcp(int len, const u_char* src, struct tcp_seg* dest)
{
    dest->src_port = cpy_2(src);
    dest->dst_port = cpy_2(src + 2);
    dest->seq_num = ntohl(cpy_4(src + 4));
    dest->ack_num = ntohl(cpy_4(src + 8));
    dest->offset = (src[12] & 0xF0) >> 4;
    dest->res = src[12] & 0xF0;
    dest->flag = src[13];
    dest->win = ntohs(cpy_2(src + 14));
    dest->chksum = ntohs(cpy_2(src + 16));
    dest->u_pnt = ntohs(cpy_2(src + 18));
    for (int i = 0; i < dest->offset - 5; i++) {
        dest->option[i] = ntohl(cpy_4(src + 20 + 4 * i));
    }

    return len - dest->offset * 4;
}

int ext_ip(int len, const u_char* src, struct ip_dtgm* dest)
{
    dest->ver = (src[0] & 0xF0) >> 4;
    dest->ihl = src[0] & 0x0F;
    dest->tos = src[1];
    dest->ttl_len = ntohs(cpy_2(src + 2));
    dest->id = ntohs(cpy_2(src + 4));
    dest->flag = 0;   // TBA
    dest->offset = 0; //TBA
    dest->ttl = src[8];
    dest->prtl = src[9];
    dest->chksum = ntohs(cpy_2(src + 10));
    dest->src_addr = cpy_4(src + 12);
    dest->dst_addr = cpy_4(src + 16);
    for (int i = 0; i < dest->ihl - 5; i++) {
        dest->option[i] = ntohl(cpy_4(src + 20 + 4 * i));
    }

    return len - dest->ihl * 4;
}

int ext_eth(int len, const u_char* src, struct eth_frame* dest)
{
    for (int i = 0; i < 6; i++) {
        dest->dst_mac[i] = src[i];
        dest->src_mac[i] = src[i + 6];
    }

    dest->eth_type = cpy_2(src + 12);

    return len - 14;
}

int main(int argc, char* argv[])
{
    pcap_t* handle;                /* Session handle */
    char* dev;                     /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    struct bpf_program fp;         /* The compiled filter */
    char filter_exp[] = ""; /* The filter expression */
    bpf_u_int32 mask;              /* Our netmask */
    bpf_u_int32 net;               /* Our IP */
    struct pcap_pkthdr* header;    /* The header that pcap gives us */
    const u_char* packet;          /* The actual packet */

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return (2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return (2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }

    int res;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0)
            continue;

        int packet_len;

        packet_len = header->len;

        struct eth_frame ef;
        struct ip_dtgm id = ef.eth_data;
        struct tcp_seg ts = id.ip_data;

        int eth_data_len;
        int ip_data_len;
        int tcp_data_len;

        eth_data_len = ext_eth(packet_len, packet, &ef);

        printf("Ethernet Frame\n");

        printf("Destination MAC Address: ");
        for (int i = 0; i < 6; i++) {
            printf("%02X", ef.dst_mac[i]);
            if (i != 5)
                printf(":");
            else
                printf("\n");
        }

        printf("Source MAC Address: ");
        for (int i = 0; i < 6; i++) {
            printf("%02X", ef.src_mac[i]);
            if (i != 5)
                printf(":");
            else
                printf("\n");
        }

        if (ef.eth_type == 0x0800) {
            printf("IP Datagram\n");

            ip_data_len = ext_ip(eth_data_len, packet + packet_len - eth_data_len, &id);

            uint32 tmp;

            printf("Source IP Address: ");

            tmp = id.src_addr;
            for (int i = 0; i < 4; i++) {
                printf("%d", (tmp & 0xFF000000) >> 24);
                tmp <<= 8;
                if (i != 3)
                    printf(".");
                else
                    printf("\n");
            }

            printf("Destination IP Address: ");

            tmp = id.dst_addr;
            for (int i = 0; i < 4; i++) {
                printf("%d", (tmp & 0xFF000000) >> 24);
                tmp <<= 8;
                if (i != 3)
                    printf(".");
                else
                    printf("\n");
            }

            if (id.prtl == 0x06) {
                printf("TCP Segment\n");

                tcp_data_len = ext_tcp(ip_data_len, packet + packet_len - ip_data_len, &ts);

                printf("Source Port: %u\n", ts.src_port);
                printf("Destination Port: %u\n", ts.dst_port);

                if (ts.src_port == 0x0050) {
                    printf("HTTP Data\n");
                    ext_http(packet + packet_len - tcp_data_len);
                }
            }
        }

        printf("\n");
    }

    pcap_close(handle);
    return (0);
}
