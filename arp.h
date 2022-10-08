//
// Created by nami on 10/6/2022.
//

#ifndef MICROPS_ARP_H
#define MICROPS_ARP_H

#include <stdint.h>

#include "net.h"
#include "ip.h"

#define ARP_RESOLVE_ERROR -1
#define ARP_RESOLVE_INCOMPLETE 0
#define ARP_RESOLVE_FOUND 1

extern int arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha);

extern int arp_init(void);

#endif //MICROPS_ARP_H
