#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[])
{
    pcap_t* handle;                /* Session handle */
    char* dev;                     /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    struct bpf_program fp;         /* The compiled filter */
    char filter_exp[] = "";        /* The filter expression */
    bpf_u_int32 mask;              /* Our netmask */
    bpf_u_int32 net;               /* Our IP */
    struct pcap_pkthdr* header;    /* The header that pcap gives us */
    const u_char* packet;          /* The actual packet */

    /* Define the device 
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return (2);
    }
    */

    if (argc != 2) {
        printf("Program Usage: ./pcap_test [Driver Device Name]\n");
        return (2);
    }

    /* Find the properties for the device */
    if (pcap_lookupnet(argv[1], &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", argv[1], errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
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

        struct ethhdr* eth_hdr;
        struct ip* ip_hdr;
        struct tcphdr* tcp_hdr;

        eth_hdr = (struct ethhdr*)packet;

        printf("Ethernet Frame\n");

        printf("Destination MAC Address: %s\n", ether_ntoa((struct ether_addr*)eth_hdr->h_dest));
        printf("Source MAC Address: %s\n", ether_ntoa((struct ether_addr*)eth_hdr->h_source));

        eth_hdr->h_proto = ntohs(eth_hdr->h_proto);

        if (eth_hdr->h_proto == ETHERTYPE_IP) {
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            ip_hdr = (struct ip*)(packet + 14);

            printf("IP Header\n");

            inet_ntop(AF_INET, (const void*)&ip_hdr->ip_src, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, (const void*)&ip_hdr->ip_dst, dst_ip, sizeof(dst_ip));
            printf("Source IP Address: %s\n", src_ip);
            printf("Destination IP Address: %s\n", dst_ip);

            //printf("Source IP Address: %s\n", inet_ntoa((struct in_addr)ip_hdr->ip_src));
            //printf("Destination IP Address: %s\n", inet_ntoa((struct in_addr)ip_hdr->ip_dst));

            ip_hdr->ip_len = ntohs(ip_hdr->ip_len);
            ip_hdr->ip_id = ntohs(ip_hdr->ip_id);
            ip_hdr->ip_off = ntohs(ip_hdr->ip_off);

            if (ip_hdr->ip_p == IPPROTO_TCP) {
                tcp_hdr = (struct tcphdr*)(packet + 14 + ip_hdr->ip_hl * 4);

                tcp_hdr->th_sport = ntohs(tcp_hdr->th_sport);
                tcp_hdr->th_dport = ntohs(tcp_hdr->th_dport);
                tcp_hdr->th_win = ntohs(tcp_hdr->th_win);
                tcp_hdr->th_sum = ntohs(tcp_hdr->th_sum);
                tcp_hdr->th_urp = ntohs(tcp_hdr->th_urp);

                printf("TCP Header\n");

                printf("Source Port Number: %d\n", tcp_hdr->th_sport);
                printf("Destination Port Number: %d\n", tcp_hdr->th_dport);

                if (tcp_hdr->th_sport == 80) {
                    char* http_data = (char*)(packet + 14 + ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4);
                    for (int i = 0; i < 20; i++) {
                        if (http_data[i] < 32 || http_data[i] > 126)
                            printf(". ");
                        else
                            printf("%c ", http_data[i]);

                        if (i == 9)
                            printf("\n");
                    }
                }
            }
        }

        printf("\n");
    }

    pcap_close(handle);
    return (0);
}
