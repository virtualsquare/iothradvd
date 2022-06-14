#ifndef IOTHRADVD_H
#define IOTHRADVD_H

#include <netinet/in.h>
#include <libvdeplug.h>
#include <stdint.h>

struct iothradvd;
struct ioth;

struct iothradata {
	uint8_t curhoplimit;
	uint8_t flags;
	uint16_t router_lifetime;
	uint32_t reachable;
	uint32_t retransmit;
	uint32_t mtu;
};

struct iothraprefix {
	struct in6_addr prefix;
	uint8_t prefixlen;
	uint8_t flags;
	uint32_t valid_time;
	uint32_t preferred_time;
};

/* start a daemon thread implementing 
 * the router advertisement protocol */
struct iothradvd *iothradvd_start(
		 struct ioth *stack, unsigned int ifindex, int period,
		 struct iothradata *data,
		 struct iothraprefix *pdata, int npdata);

/* start a daemon thread implementing 
 * the router advertisement protocol 
 * (vde + IPv6 emulation mode) */
struct iothradvd *iothradvd_vdestart(
		 char *vnl, void *macaddr, int period,
		 struct iothradata *data,
		 struct iothraprefix *pdata, int npdata);

void iothradvd_stop(struct iothradvd *radvd);

#endif

