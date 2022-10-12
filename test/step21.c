#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stddef.h>
#include <errno.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"
#include "test.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s) {
    (void) s;
    terminate = 1;
    net_raise_event();
}

static int setup() {
    struct net_device *dev_loopback, *dev_ether;
    struct ip_iface *iface_loopback, *iface_tap0;

    signal(SIGINT, on_signal);
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }

    dev_loopback = loopback_init();

    if (!dev_loopback) {
        errorf("loopback_init() failure");
        return -1;
    }

    iface_loopback = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface_loopback) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }

    if (ip_iface_register(dev_loopback, iface_loopback) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }

    dev_ether = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev_ether) {
        errorf("ether_tap_init() failure");
        return -1;
    }

    iface_tap0 = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface_tap0) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }

    if (ip_iface_register(dev_ether, iface_tap0) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }

    if (ip_route_set_default_gateway(iface_tap0, DEFAULT_GATEWAY) == -1) {
        errorf("ip_route_set_default_gateway() failed");
        return -1;
    }

    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }

    return 0;
}

static void cleanup() {
    net_shutdown();
}

int main(int argc, char *argv[]) {
    int soc;
    struct ip_endpoint local, foreign;
    uint8_t buf[1024];
    ssize_t ret;
    char ep[IP_ENDPOINT_STR_LEN];

    if (setup() == -1) {
        errorf("setup() failed");
        return -1;
    }

    soc = udp_open();
    if (soc == -1) {
        errorf("udp_open() failed");
        return -1;
    }

    ip_endpoint_pton("0.0.0.0:7", &local);

    if (udp_bind(soc, &local) == -1) {
        errorf("udp_bind() failed");
        udp_close(soc);
        return -1;
    }

    debugf("waiting for data...");
    while (!terminate) {
        ret = udp_receive_from(soc, buf, sizeof(buf), &foreign);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }

            errorf("udp_receive_from failed");
            break;
        }

        debugf("%zd bytes data from %s", ret, ip_endpoint_ntop(&foreign, ep, sizeof(ep)));
        hexdump(stderr, buf, ret);
        if (udp_send_to(soc, buf, ret, &foreign) == -1) {
            errorf("udp_send_to() failed");
            break;
        }
    }

    udp_close(soc);
    cleanup();

    return 0;

    cleanup();
    return 0;
}