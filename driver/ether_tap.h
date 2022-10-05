#ifndef MICROPS_ETHER_TAP_H
#define MICROPS_ETHER_TAP_H

#include "net.h"

extern struct net_device * ether_tap_init(const char *name, const char *addr);

#endif //MICROPS_ETHER_TAP_H
