#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "ip.h"
#include "tcp.h"

#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)

struct pseudo_hdr {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t offset;
    uint8_t flag;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

static char *tcp_flag_ntoa(uint8_t flag) {
    static char str[9];

    snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
             TCP_FLG_ISSET(flag, TCP_FLG_URG) ? 'U' : '-',
             TCP_FLG_ISSET(flag, TCP_FLG_ACK) ? 'A' : '-',
             TCP_FLG_ISSET(flag, TCP_FLG_PSH) ? 'P' : '-',
             TCP_FLG_ISSET(flag, TCP_FLG_RST) ? 'R' : '-',
             TCP_FLG_ISSET(flag, TCP_FLG_SYN) ? 'S' : '-',
             TCP_FLG_ISSET(flag, TCP_FLG_FIN) ? 'F' : '-'
    );

    return str;
}

static void tcp_dump(const uint8_t *data, size_t len) {
    struct tcp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct tcp_hdr *) data;
    fprintf(stderr, "        src_addr: %u\n", ntoh16(hdr->src_port));
    fprintf(stderr, "        dst_addr: %u\n", ntoh16(hdr->src_port));
    fprintf(stderr, "        seq: %u\n", ntoh32(hdr->seq_num));
    fprintf(stderr, "        ack: %u\n", ntoh32(hdr->ack_num));
    fprintf(stderr, "     offset: 0x%02x (%d)\n", hdr->offset, (hdr->offset >> 4) << 2);
    fprintf(stderr, "       flag: 0x%02x (%s)\n", hdr->flag, tcp_flag_ntoa(hdr->flag));
    fprintf(stderr, "     window: %u\n", ntoh16(hdr->window));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->checksum));
    fprintf(stderr, "     urgent: %u\n", ntoh16(hdr->urgent_ptr));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

static void tcp_input(const uint8_t *data, size_t len, ip_addr_t src_addr, ip_addr_t dst_addr, struct ip_iface *iface) {
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t pseudo_checksum;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;
    }

    hdr = (struct tcp_hdr *) data;

    pseudo.src_addr = src_addr;
    pseudo.dst_addr = dst_addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.len = hton16(len);

    pseudo_checksum = ~cksum16((uint16_t *) &pseudo, sizeof(pseudo), 0);

    if (cksum16((uint16_t *) hdr, len, pseudo_checksum) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->checksum),
               ntoh16(cksum16((uint16_t *) hdr, len, -hdr->checksum + pseudo_checksum)));
        return;
    }

    if (src_addr == IP_ADDR_BROADCAST || dst_addr == IP_ADDR_BROADCAST) {
        errorf("source or destination address is broadcast address: %s=>%s",
               ip_addr_ntop(src_addr, addr1, sizeof(addr1)), ip_addr_ntop(dst_addr, addr2, sizeof(addr2)));
        return;
    }

    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)", ip_addr_ntop(src_addr, addr1, sizeof(addr1)), ntoh16(hdr->src_port),
           ip_addr_ntop(dst_addr, addr2, sizeof(addr2)), ntoh16(hdr->dst_port), len, len - sizeof(*hdr));
    tcp_dump(data, len);

    return;
}

int tcp_init() {
    if (ip_protocol_register(IP_PROTOCOL_TCP, tcp_input) == -1) {
        errorf("ip_protocol_register() failed");
        return -1;
    }
    return 0;
}