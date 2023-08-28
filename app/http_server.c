#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "sock.h"
#include "http.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test/test.h"
#include "platform.h"

#define BUFFER_SIZE 1024

static volatile sig_atomic_t terminate;

static void
on_signal(int s) {
    (void) s;
    terminate = 1;
    net_interrupt();
}

static int
setup(void) {
    struct net_device *dev;
    struct ip_iface *iface;

    signal(SIGINT, on_signal);
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev) {
        errorf("ether_tap_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1) {
        errorf("ip_route_set_default_gateway() failure");
        return -1;
    }
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    return 0;
}

int handle_request(int client_socket) {
    char buffer[BUFFER_SIZE];
    char tmp_buffer[BUFFER_SIZE];
    ssize_t bytes_received = 0;
    ssize_t tmp_bytes_received = 0;

    // リクエストメッセージが完成するまで繰り返し受信する（for nc command）
    memset(buffer, 0, BUFFER_SIZE);
    memset(tmp_buffer, 0, BUFFER_SIZE);
    while ((tmp_bytes_received = sock_recv(client_socket, tmp_buffer, BUFFER_SIZE)) > 0) { ;
        memcpy(&buffer[bytes_received], tmp_buffer, tmp_bytes_received);
        bytes_received += tmp_bytes_received;

        // 改行が2つ連続するまでキャプチャする
        if (strncmp(&buffer[bytes_received - 4], "\r\n\r\n", 4) == 0) {
            break;
        }

        memset(tmp_buffer, 0, BUFFER_SIZE);
    }

//    infof("http request message: \n%s", buffer);

    struct http_request* request_object;

    request_object = memory_alloc(sizeof &request_object);

    int status_code = parse_http_message(buffer, request_object);

    // response
    char response_body[BUFFER_SIZE];

    if (status_code == 200) {
        strcpy(response_body, "Hello, world!\r\n");
    } else {
        strcpy(response_body, "Server Error\r\n");
    }

    struct http_header *response_header = memory_alloc(sizeof(struct http_header));
    strcpy(response_header->name, "Content-Length");
    sprintf(response_header->value, "%lu", strlen(response_body));

    char response_message[BUFFER_SIZE];
    memset(response_message, 0, BUFFER_SIZE);
    create_response_message(response_message, status_code, response_header, response_body);

    // Respond to the client
    sock_send(client_socket, response_message, strlen(response_message));

    return 0;
}

int
main(int argc, char *argv[]) {
    int soc, acc;
    long int port;
    struct sockaddr_in local = {.sin_family=AF_INET}, foreign;
    int foreignlen;
    char addr[SOCKADDR_STR_LEN];
    uint8_t buf[1024];
    ssize_t ret;

    /*
     * Parse command line parameters
     */
    switch (argc) {
        case 3:
            if (ip_addr_pton(argv[argc - 2], &local.sin_addr) == -1) {
                errorf("ip_addr_pton() failure, addr=%s", optarg);
                return -1;
            }
            /* fall through */
        case 2:
            port = strtol(argv[argc - 1], NULL, 10);
            if (port < 0 || port > UINT16_MAX) {
                errorf("invalid port, port=%s", optarg);
                return -1;
            }
            local.sin_port = hton16(port);
            break;
        default:
            fprintf(stderr, "Usage: %s [addr] port\n", argv[0]);
            return -1;
    }
    /*
     * Setup protocol stack
     */
    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }
    /*
     *  Application Code
     */
    soc = sock_open(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (soc == -1) {
        errorf("sock_open() failure");
        return -1;
    }
    if (sock_bind(soc, (struct sockaddr *) &local, sizeof(local)) == -1) {
        errorf("sock_bind() failure");
        return -1;
    }
    if (sock_listen(soc, 1) == -1) {
        errorf("sock_listen() failure");
        return -1;
    }

    while (!terminate) {
        foreignlen = sizeof(foreignlen);
        acc = sock_accept(soc, (struct sockaddr *) &foreign, &foreignlen);
        if (acc == -1) {
            errorf("sock_accept() failure");
            return -1;
        }
        infof("connection accepted, foreign=%s", sockaddr_ntop((struct sockaddr *) &foreign, addr, sizeof(addr)));

        handle_request(acc);

        // Close the client socket
        close(acc);
    }

    sock_close(acc);
    sock_close(soc);
    /*
     * Cleanup protocol stack
     */
    net_shutdown();
    return 0;
}
