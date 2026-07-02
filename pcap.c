#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>

#define ETHERNET_HEADER_LEN 14
#define ETHERTYPE_IP 0x0800
#define IPPROTO_TCP 6

struct ethernet_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
} __attribute__((packed));

struct ip_header {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed));

struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} __attribute__((packed));

void print_mac(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int is_http_payload(const uint8_t *payload, int len) {
    if (len < 4) return 0;

    const char *methods[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
        "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", "HTTP/"
    };

    for (int i = 0; i < 10; i++) {
        int mlen = strlen(methods[i]);
        if (len >= mlen && memcmp(payload, methods[i], mlen) == 0) {
            return 1;
        }
    }

    return 0;
}

void print_http_message(const uint8_t *payload, int len) {
    printf("\n[HTTP Message]\n");

    for (int i = 0; i < len; i++) {
        if (isprint(payload[i]) || payload[i] == '\n' || payload[i] == '\r' || payload[i] == '\t') {
            putchar(payload[i]);
        } else {
            putchar('.');
        }
    }

    printf("\n");
}

void packet_handler(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet) {
    (void)args;

    if (header->caplen < ETHERNET_HEADER_LEN) {
        return;
    }

    const struct ethernet_header *eth = (const struct ethernet_header *)packet;

    if (ntohs(eth->type) != ETHERTYPE_IP) {
        return;
    }

    if (header->caplen < ETHERNET_HEADER_LEN + sizeof(struct ip_header)) {
        return;
    }

    const struct ip_header *ip = (const struct ip_header *)(packet + ETHERNET_HEADER_LEN);

    int ip_header_len = (ip->ver_ihl & 0x0F) * 4;

    if (ip_header_len < 20) {
        return;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return;
    }

    if (header->caplen < ETHERNET_HEADER_LEN + ip_header_len + sizeof(struct tcp_header)) {
        return;
    }

    uint16_t ip_total_len = ntohs(ip->total_len);

    if (ip_total_len < ip_header_len + 20) {
        return;
    }

    const struct tcp_header *tcp =
        (const struct tcp_header *)(packet + ETHERNET_HEADER_LEN + ip_header_len);

    int tcp_header_len = ((tcp->data_offset >> 4) & 0x0F) * 4;

    if (tcp_header_len < 20) {
        return;
    }

    int payload_offset = ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len;
    int payload_len = ip_total_len - ip_header_len - tcp_header_len;

    if (payload_len <= 0) {
        return;
    }

    if (header->caplen < (unsigned int)payload_offset) {
        return;
    }

    int captured_payload_len = header->caplen - payload_offset;
    if (captured_payload_len < payload_len) {
        payload_len = captured_payload_len;
    }

    const uint8_t *payload = packet + payload_offset;

    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip->src_ip;
    dst_addr.s_addr = ip->dst_ip;

    printf("\n================ Packet Captured ================\n");

    printf("[Ethernet Header]\n");
    printf("Src MAC : ");
    print_mac(eth->src_mac);
    printf("\nDst MAC : ");
    print_mac(eth->dst_mac);
    printf("\n");

    printf("\n[IP Header]\n");
    printf("Src IP  : %s\n", inet_ntoa(src_addr));
    printf("Dst IP  : %s\n", inet_ntoa(dst_addr));

    printf("\n[TCP Header]\n");
    printf("Src Port: %u\n", ntohs(tcp->src_port));
    printf("Dst Port: %u\n", ntohs(tcp->dst_port));

    printf("\n[Length Info]\n");
    printf("IP Header Length : %d bytes\n", ip_header_len);
    printf("TCP Header Length: %d bytes\n", tcp_header_len);
    printf("Payload Length   : %d bytes\n", payload_len);

    if (is_http_payload(payload, payload_len)) {
        print_http_message(payload, payload_len);
    } else {
        printf("\n[HTTP Message]\n");
        printf("HTTP 형식의 평문 메시지가 아니거나, HTTPS/TLS로 암호화된 데이터입니다.\n");
    }

    printf("=================================================\n");
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp port 80";
    bpf_u_int32 net = 0;

    if (argc != 2) {
        printf("Usage: sudo %s <network interface>\n", argv[0]);
        printf("Example: sudo %s enp0s3\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "This program only supports Ethernet packets.\n");
        pcap_close(handle);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }

    printf("Sniffing on interface: %s\n", dev);
    printf("Filter: TCP only\n");

    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}