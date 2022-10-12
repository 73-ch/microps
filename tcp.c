#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include "platform.h"

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

#define TCP_PCB_SIZE 16

#define TCP_PCB_STATE_FREE 0
#define TCP_PCB_STATE_CLOSED 1
#define TCP_PCB_STATE_LISTEN 2
#define TCP_PCB_STATE_SYN_SENT 3
#define TCP_PCB_STATE_SYN_RECEIVED 4
#define TCP_PCB_STATE_ESTABLISHED 5
#define TCP_PCB_STATE_FIN_WAIT1 6
#define TCP_PCB_STATE_FIN_WAIT2 7
#define TCP_PCB_STATE_CLOSING 8
#define TCP_PCB_STATE_TIME_WAIT 9
#define TCP_PCB_STATE_CLOSE_WAIT 10
#define TCP_PCB_STATE_LAST_ACK 11

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

struct tcp_segment_info {
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t length;
    uint16_t window;
    uint16_t urgent;
};

struct tcp_pcb {
    int state;
    struct ip_endpoint local;
    struct ip_endpoint foreign;
    struct {
        uint32_t next_seq;
        uint32_t una;
        uint16_t window;
        uint16_t urgent;
        uint32_t wl1;
        uint32_t wl2;
    } send;
    uint32_t iss;
    struct {
        uint32_t next_seq;
        uint16_t window;
        uint16_t urgent;
    } receive;
    uint32_t irs;
    uint16_t mtu;
    uint16_t mss;
    uint8_t receive_buf[65535];
    struct sched_ctx ctx;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct tcp_pcb pcbs[TCP_PCB_SIZE];

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

/*
 * TCP Protocol Control Block(PCB)
 * NOTE: TCP PCB functions must be called after mutex locked
 */

static struct tcp_pcb *tcp_pcb_alloc() {
    struct tcp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == TCP_PCB_STATE_FREE) {
            pcb->state = TCP_PCB_STATE_CLOSED;
            sched_ctx_init(&pcb->ctx);
            return pcb;
        }
    }
    return NULL;
}

static void tcp_pcb_release(struct tcp_pcb *pcb) {
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    if (sched_ctx_destroy(&pcb->ctx) == -1) {
        sched_wakeup(&pcb->ctx);
        return;
    }

    debugf("released, local=%s, foreign=%s", ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)),
           ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));

    /* pcb->state is set to TCP_PCB_STATE_FREE(0) */
    memset(pcb, 0, sizeof(*pcb));
}

static struct tcp_pcb *tcp_pcb_select(struct ip_endpoint *local, struct ip_endpoint *foreign) {
    struct tcp_pcb *pcb, *listen_pcb = NULL;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if ((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == local->addr) && pcb->local.port == local->port) {
            if (!foreign) {
                return pcb;
            }
            if (pcb->foreign.addr == foreign->addr && pcb->foreign.port == foreign->port) {
                return pcb;
            }
            if (pcb->state == TCP_PCB_STATE_LISTEN) {
                if (pcb->foreign.addr == IP_ADDR_ANY && pcb->foreign.port == 0) {
                    /* LISTENed with wildcard foreign address/port */
                    listen_pcb = pcb;
                }
            }
        }
    }

    return listen_pcb;
}

static struct tcp_pcb *tcp_pcb_get(int id) {
    struct tcp_pcb *pcb;

    if (id < 0 || id <= (int) countof(pcbs)) {
        /* out of range */
        return NULL;
    }

    pcb = &pcbs[id];
    if (pcb->state == TCP_PCB_STATE_FREE) {
        return NULL;
    }
    return pcb;
}

static int tcp_pcb_id(struct tcp_pcb *pcb) {
    return indexof(pcbs, pcb);
}

static ssize_t
tcp_output_segment(uint32_t seq_num, uint32_t ack_num, uint8_t flag, uint16_t window, uint8_t *data, size_t len,
                   struct ip_endpoint *local, struct ip_endpoint *foreign) {
    uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t pseudo_checksum;
    uint16_t total_length;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    hdr = (struct tcp_hdr *) buf;
    hdr->src_port = local->port;
    hdr->dst_port = foreign->port;
    hdr->seq_num = hton32(seq_num);
    hdr->ack_num = hton32(ack_num);
    hdr->offset = (sizeof(*hdr) >> 2) << 4;
    hdr->flag = flag;
    hdr->window = hton16(window);
    hdr->checksum = 0;
    hdr->urgent_ptr = 0;

    memcpy(hdr + 1, data, len);

    /* calc checksum */
    total_length = len + sizeof(*hdr);
    pseudo.src_addr = local->addr;
    pseudo.dst_addr = foreign->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.len = hton16(total_length);
    pseudo_checksum = ~cksum16((uint16_t *) &pseudo, sizeof(pseudo), 0);
    hdr->checksum = cksum16((uint16_t *) hdr, sizeof(*hdr), pseudo_checksum);

    debugf("%s => %s, len=%zu (payload=%zu)", ip_endpoint_ntop(local, ep1, sizeof(ep1)),
           ip_endpoint_ntop(foreign, ep2, sizeof(ep2)), total_length, len);
    tcp_dump((uint8_t *) hdr, total_length);

    if (ip_output(IP_PROTOCOL_TCP, (uint8_t *) hdr, total_length, local->addr, foreign->addr) == -1) {
        errorf("ip_output() failed");
        return -1;
    }

    return len;
}

static ssize_t tcp_output(struct tcp_pcb *pcb, uint8_t flag, uint8_t *data, size_t len) {
    uint32_t seq_num;

    seq_num = pcb->send.next_seq;
    if (TCP_FLG_ISSET(flag, TCP_FLG_SYN)) {
        seq_num = pcb->iss;
    }

    if (TCP_FLG_ISSET(flag, TCP_FLG_SYN | TCP_FLG_FIN) || len) {
        /* TODO: add retransmission queue */
    }

    return tcp_output_segment(seq_num, pcb->receive.next_seq, flag, pcb->receive.window, data, len, &pcb->local,
                              &pcb->foreign);
}

/* rfc 793 - section 3.9 [Event Processing > SEGMENT ARRIVES] */
static void tcp_segment_arrives(struct tcp_segment_info *segment_info, uint8_t flags, uint8_t *data, size_t len,
                                struct ip_endpoint *local, struct ip_endpoint *foreign) {
    struct tcp_pcb *pcb;

    pcb = tcp_pcb_select(local, foreign);
    if (!pcb || pcb->state == TCP_PCB_STATE_CLOSED) {
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
            return;
        }
        if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
            tcp_output_segment(0, segment_info->seq_num + segment_info->length, TCP_FLG_RST | TCP_FLG_ACK, 0, NULL, 0,
                               local, foreign);
        } else {
            tcp_output_segment(segment_info->ack_num, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
        }
        return;
    }

    switch (pcb->state) {
        case TCP_PCB_STATE_LISTEN:
            /* 1st check for RST */
            if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
                return;
            }
            /* 2nd check for ACK */
            if (TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
                tcp_output_segment(segment_info->ack_num, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
            }
            /* 3rd check for SYN */
            if (TCP_FLG_ISSET(flags, TCP_FLG_SYN)) {
                /* ignore: security/compartment check */
                /* ignore: precedence check */
                pcb->local = *local;
                pcb->foreign = *foreign;
                pcb->receive.window = sizeof(pcb->receive_buf);
                pcb->receive.next_seq = segment_info->seq_num + 1;
                pcb->irs = segment_info->seq_num;
                pcb->iss = random();
                tcp_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
                pcb->send.next_seq = pcb->iss + 1;
                pcb->send.una = pcb->iss;
                pcb->state = TCP_PCB_STATE_SYN_RECEIVED;
                /* ignore: Note that any other incoming control or data */
                /* (combined with SYN) will be processed in he SYN-RECEIVED state, */
                /* but processing of SYN and ACK should not be repeated. */
                return;
            }
            /* 4th other text or control */
            /* drop segment */
            return;

        case TCP_PCB_STATE_SYN_SENT:
            /* 1st check the ACK bit */

            /* 2nd check the RST bi t*/

            /* 3rd check security and precedence (ignore) */

            /* 4th check the SYN bit */

            /* 5th, if neither of the SYN or RST bits is set then drop the segment and return */

            /* drop segment */
            return;
    }

    /* Other wise */


    /* 1st check sequence number */

    /* 2nd check the RST bit */

    /* 3rd check security and precedence (ignore) */

    /* 4th check the SYN bit */

    /* 5th check the ACK field */
    if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
        /* drop segment */
        return;
    }
    switch (pcb->state) {
        case TCP_PCB_STATE_SYN_RECEIVED:
            /* check correctness of ack for sent segment */
            if (pcb->send.una <= segment_info->ack_num && segment_info->ack_num <= pcb->send.next_seq) {
                pcb->state = TCP_PCB_STATE_ESTABLISHED;
                sched_wakeup(&pcb->ctx);
            } else {
                tcp_output_segment(segment_info->ack_num, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
                return;
            }
            break;
    }

    /* 6th check the URG bit (ignore) */

    /* 7th process the segment text */

    /* 8th check the FIN bit */

}

static void event_handler(void *args) {
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state != TCP_PCB_STATE_FREE) {
            sched_interrupt(&pcb->ctx);
        }
    }
    mutex_unlock(&mutex);
}

static void tcp_input(const uint8_t *data, size_t len, ip_addr_t src_addr, ip_addr_t dst_addr, struct ip_iface *iface) {
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t pseudo_checksum;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    struct ip_endpoint local, foreign;
    uint16_t header_length;
    struct tcp_segment_info segment_info;

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

    local.addr = dst_addr;
    local.port = hdr->dst_port;
    foreign.addr = src_addr;
    foreign.port = hdr->src_port;
    header_length = (hdr->offset >> 4) << 2;
    segment_info.seq_num = ntoh32(hdr->seq_num);
    segment_info.ack_num = ntoh32(hdr->ack_num);
    segment_info.length = len - header_length;
    if (TCP_FLG_ISSET(hdr->flag, TCP_FLG_SYN)) {
        segment_info.length++; /* SYN flag consumes one sequence number */
    }
    if (TCP_FLG_ISSET(hdr->flag, TCP_FLG_FIN)) {
        segment_info.length++; /* FIN flag consumes one sequence number */
    }
    segment_info.window = ntoh16(hdr->window);
    segment_info.urgent = ntoh16(hdr->urgent_ptr);
    mutex_lock(&mutex);
    tcp_segment_arrives(&segment_info, hdr->flag, (uint8_t *) hdr + header_length, len - header_length, &local,
                        &foreign);
    mutex_unlock(&mutex);
}

int tcp_init() {
    if (ip_protocol_register(IP_PROTOCOL_TCP, tcp_input) == -1) {
        errorf("ip_protocol_register() failed");
        return -1;
    }
    net_event_subscribe(event_handler, NULL);
    return 0;
}

/*
 * TCP User Command (RFC793)
 */

int tcp_open_rfc793(struct ip_endpoint *local, struct ip_endpoint *foreign, int active) {
    struct tcp_pcb *pcb;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];
    int state, id;

    mutex_lock(&mutex);
    pcb = tcp_pcb_alloc();
    if (!pcb) {
        errorf("tcp_pcb_alloc() failed");
        mutex_unlock(&mutex);
        return -1;
    }

    if (active) {
        errorf("active open does not implement");
        tcp_pcb_release(pcb);
        mutex_unlock(&mutex);
        return -1;
    } else {
        debugf("passive open: local=%s, waiting for connection ...", ip_endpoint_ntop(local, ep1, sizeof(ep1)));

        pcb->local = *local;
        if (foreign) {
            pcb->foreign = *foreign;
        }

        pcb->state = TCP_PCB_STATE_LISTEN;
    }

    AGAIN:
    state = pcb->state;

    /* waiting for state changed */
    while (pcb->state == state) {
        if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
            debugf("interrupted");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            mutex_unlock(&mutex);
            errno = EINTR;
            return -1;
        }
    }

    if (pcb->state != TCP_PCB_STATE_ESTABLISHED) {
        if (pcb->state == TCP_PCB_STATE_SYN_RECEIVED) {
            goto AGAIN;
        }
        errorf("open error: %d", pcb->state);
        pcb->state = TCP_PCB_STATE_CLOSED;
        tcp_pcb_release(pcb);
        mutex_unlock(&mutex);
        return -1;
    }

    id = tcp_pcb_id(pcb);
    debugf("connection established: local=%s, foreign=%s", ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)),
           ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
    mutex_unlock(&mutex);
    return id;
}

int tcp_close(int id) {
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }

    tcp_output(pcb, TCP_FLG_RST, NULL, 0);
    tcp_pcb_release(pcb);
    mutex_unlock(&mutex);
    return 0;
}