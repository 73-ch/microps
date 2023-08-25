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

    // リクエストメッセージのパース
    char *start_line;
    char *header_message;
    char *body_message;

    start_line = buffer;
    char *start_line_end = strstr(buffer, "\r\n");
    *start_line_end = '\0';

    header_message = start_line_end + strlen("\r\n");
    char *header_message_end= strstr(header_message, "\r\n\r\n");
    *header_message_end = '\0';

    body_message = header_message_end + strlen("\r\n\r\n");

    // 開始行のパース
    char *tmp_method;
    char *tmp_target;
    char *header_parse_restart = NULL;
    /* method */
    tmp_method = strtok(start_line, " ");
    if (tmp_method == NULL) {
        errorf("get method error");
        return -1;
    }
    int method;
    method = parse_http_method(tmp_method);
    if (method < 0) {
        errorf("method parse error");
        return -1;
    }

    /* target */
    tmp_target = strtok(NULL, " ");
    if (tmp_target == NULL) {
        printf("get target error\n");
        return -1;
    }

    /* http version */
    int http_version;
    char *tmp_http_version;
    tmp_http_version = strtok(NULL, " ");
    http_version = parse_http_version(tmp_http_version);


    // parse header
    char *tmp_header_line;
    struct http_header *header = NULL;

    char *tmp_header_name;
    char *tmp_header_value;

    tmp_header_line = strtok_r(header_message, "\r\n", &header_parse_restart);

    while (tmp_header_line != NULL) {
        struct http_header *new_header = memory_alloc(sizeof(struct http_header *));

        if (!new_header) {
            errorf("memory_alloc() failure");
            return -1;
        }

        tmp_header_name = strtok(tmp_header_line, ": ");
        tmp_header_value = strtok(NULL, "");

        new_header->header_name = memory_alloc(sizeof(tmp_header_name));
        new_header->value = memory_alloc(sizeof(tmp_header_value-1));

        strcpy(new_header->header_name, tmp_header_name);
        strcpy(new_header->value++, tmp_header_value);
        if (header) {
            new_header->next = header;
        }

        header = new_header;

        tmp_header_line = strtok_r(NULL, "\r\n", &header_parse_restart);
    }


    // HTTP Requestの表示
    infof("HTTP Request: ");
    infof("method: %s, target: %s, version: %s", http_method_name(method), tmp_target, http_version_name(http_version));

    struct http_header* tmp_header = header;
    while (tmp_header != NULL) {
        infof("header: %s: %s", tmp_header->header_name, tmp_header->value);
        tmp_header  = tmp_header->next;
    }


    // check required header
    if (http_version >= HTTP_VERSION_1_1) {
        tmp_header = header;
        while (tmp_header != NULL) {
            if (strcmp(tmp_header->header_name, "Host") == 0) {
                break;
            }
            tmp_header = tmp_header->next;
        }
        if (tmp_header == NULL) {
            // bad request
            errorf("Host header is required.");
            return -1;
        }
    }


    // Respond to the client
    const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello, world!\r\n";
    sock_send(client_socket, response, strlen(response));

    // Close the client socket
    close(client_socket);

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
    foreignlen = sizeof(foreignlen);
    acc = sock_accept(soc, (struct sockaddr *) &foreign, &foreignlen);
    if (acc == -1) {
        errorf("sock_accept() failure");
        return -1;
    }
    infof("connection accepted, foreign=%s", sockaddr_ntop((struct sockaddr *) &foreign, addr, sizeof(addr)));

    handle_request(acc);

    sock_close(acc);
    sock_close(soc);
    /*
     * Cleanup protocol stack
     */
    net_shutdown();
    return 0;
}
