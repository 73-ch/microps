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
#include "tcp.h"

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
    if (setup() == -1) {
        errorf("setup() failed");
        return -1;
    }

    while (!terminate) {
        sleep(1);
    }

    cleanup();
    return 0;
}