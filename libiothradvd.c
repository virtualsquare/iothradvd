/*
 *   libiothradvd.c: router advertisement library for ioth
 *
 *   Copyright 2022 Renzo Davoli - Virtual Square Team
 *   University of Bologna - Italy
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; 
 * If not, see <http://www.gnu.org/licenses/>. 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <time.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <ioth.h>
#include <iothconf.h>
#include <iothaddr.h>
#include <iothradvd.h>

struct iothradvd {
	VDECONN *conn;
  pthread_t tid;
  int period;
  int sd;
  char *packet;
  size_t packetlen;
};

/* it is not INT64_MAX: glibc supports conversions up to year 2147483647 */
#define MAX_TIME \
  ((sizeof(time_t) == 8) ? 67767976233521999L : INT32_MAX)

#define eth_allnodes {0x33,0x33,0x00,0x01,0x00,0x01}
#define eth_allrouters {0x33,0x33,0x00,0x01,0x00,0x02}
struct in6_addr ll_allnodes = {.s6_addr = {0xff,0x02, [15]=0x01}};
struct in6_addr ll_allrouters = {.s6_addr = {0xff,0x02, [15]=0x02}};

/* IPv6 Packet structure for VDE + IPv6 emulation */
struct ip6_pkt {
  struct ether_header ethh;
  struct ip6_hdr ipv6h __attribute__((__packed__));
  char payload[];
};

static void ra_addheader(FILE *f, struct iothradata *data) {
	struct nd_router_advert ra = {
		.nd_ra_type = ND_ROUTER_ADVERT,
		.nd_ra_code = 0,
		.nd_ra_curhoplimit = data->curhoplimit,
		.nd_ra_flags_reserved = data->flags,
		.nd_ra_reachable = data->reachable,
		.nd_ra_retransmit = data->retransmit};
	ra.nd_ra_router_lifetime = htons(data->router_lifetime);
	fwrite(&ra, sizeof(ra), 1, f);
}

static void ra_addprefix(FILE *f, struct iothraprefix *pdata) {
  struct nd_opt_prefix_info pre = {
    .nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION,
    .nd_opt_pi_len = sizeof(struct nd_opt_prefix_info) / 8,
    .nd_opt_pi_prefix_len = pdata->prefixlen,
    .nd_opt_pi_flags_reserved = pdata->flags,
    .nd_opt_pi_valid_time = htonl(pdata->valid_time),
    .nd_opt_pi_preferred_time = htonl(pdata->preferred_time),
		.nd_opt_pi_prefix = pdata->prefix,
  };
  fwrite(&pre, sizeof(pre), 1, f);
  return;
}

static void ra_addslla(FILE *f, void *slla) {
  if (slla) {
    struct nd_opt_hdr hdr = {
      .nd_opt_type = ND_OPT_SOURCE_LINKADDR,
      .nd_opt_len = (sizeof(struct nd_opt_hdr) + 6) / 8
    };
    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(slla, 6, 1, f);
  }
}

static void ra_addmtu(FILE *f, uint32_t mtu) {
  if (mtu) {
    struct nd_opt_mtu optmtu = {
      .nd_opt_mtu_type = ND_OPT_MTU,
      .nd_opt_mtu_len = sizeof(struct nd_opt_mtu) / 8,
      .nd_opt_mtu_mtu = htonl(mtu)
    };
    fwrite(&optmtu, sizeof(optmtu), 1, f);
  }
}

/* checksum computation helper function */
static unsigned int chksum(unsigned int sum, const void *vbuf, size_t len) {
  unsigned const char *buf = vbuf;
  size_t i;
  for (i = 0; i < len; i++)
    sum += (i % 2) ? buf[i] : buf[i] << 8;
  while (sum >> 16)
    sum = (sum >> 16) + (sum & 0xffff);
  return sum;
}

static int icmp_checksum(struct ip6_pkt *pkt) {
	static const char isimcp[2] = {0x00,0x3a};
	unsigned int sum = 0;
	sum = chksum(sum, pkt->ipv6h.ip6_src.s6_addr, 16);
	sum = chksum(sum, pkt->ipv6h.ip6_dst.s6_addr, 16);
	sum = chksum(sum, isimcp, 2);
	sum = chksum(sum, &pkt->ipv6h.ip6_plen, 2);
	sum = chksum(sum, &pkt->payload, ntohs(pkt->ipv6h.ip6_plen));
	return sum;
}

static void send_advertisement(struct iothradvd *radvd, struct sockaddr_in6 *dest, socklen_t destlen) {
	if (radvd->conn == NULL) {
		/* libioth mode */
		/* (the stack computes the checksum) */
		ioth_sendto(radvd->sd, radvd->packet, radvd->packetlen, 0, (void *) dest, destlen);
	} else {
		/* VDE + IPv6 emulation mode */
		struct ip6_pkt *outpkt = (void *) radvd->packet;
		struct icmp6_hdr *icmphdr = (void *) outpkt->payload;
		/* set up the variable fields */
		int payloadlen = radvd->packetlen - sizeof(struct ip6_pkt);
		outpkt->ipv6h.ip6_plen = htons(payloadlen);
		outpkt->ipv6h.ip6_dst = dest->sin6_addr;
		/* compute the checksum */
		icmphdr->icmp6_cksum = 0;
		icmphdr->icmp6_cksum = htons(~ icmp_checksum(outpkt));
		/* send! */
		vde_send(radvd->conn, radvd->packet, radvd->packetlen, 0);
	}
}

static int ck_inpkt(struct ip6_pkt *inpkt) {
	struct icmp6_hdr *icmphdr = (void *) inpkt->payload;
  static uint8_t ra_ethernet_addr[]={0x33,0x33,0x00,0x00,0x00,0x02};
  if (memcmp(inpkt->ethh.ether_dhost, ra_ethernet_addr, ETH_ALEN) != 0)
    return 0;
  if (ntohs(inpkt->ethh.ether_type) != 0x86dd) return 0; // this is not IPv6
  if (inpkt->ipv6h.ip6_vfc >> 4 != 6) return 0; //this is not IPv6
  if (inpkt->ipv6h.ip6_nxt != IPPROTO_ICMPV6) return 0; //this is not ICMPv6
	if (icmphdr->icmp6_type != ND_ROUTER_SOLICIT) return 0; //this is not a RS
	if (icmp_checksum(inpkt) != 0xffff) return 0; // the checksum is wrong
  return 1;
}

static void recv_solicitation(struct iothradvd *radvd) {
	if (radvd->conn == NULL) {
		/* libioth mode: just send back the RA packet */
		struct sockaddr_in6 client;
		socklen_t clientlen = sizeof(client);

		int rv = ioth_recvfrom(radvd->sd, NULL, 0, MSG_PEEK|MSG_TRUNC, (void *) &client, &clientlen);
		uint8_t inbuf[rv];
		rv = ioth_recvfrom(radvd->sd, inbuf, rv, 0, (void *) &client, &clientlen);
		struct icmp6_hdr *hdr = (void *) inbuf;
		if (rv >= (int) sizeof(struct icmp6_hdr) && hdr->icmp6_type == ND_ROUTER_SOLICIT && hdr->icmp6_code == 0)
			send_advertisement(radvd, &client, clientlen);
	} else {
		/* VDE IPv6 emulation */
		uint8_t vdepkt[VDE_MAXMTU];
		ssize_t vdepktlen = vde_recv(radvd->conn, vdepkt, VDE_MAXMTU, 0);
		if (vdepktlen >= (ssize_t) (sizeof(struct ip6_pkt) + sizeof(struct icmp6_hdr))) {
			struct ip6_pkt *inpkt = (void *) vdepkt;
			/* select the Router Soliciation requests */
			if (ck_inpkt(inpkt)) {
				struct sockaddr_in6 dest = {.sin6_addr = inpkt->ipv6h.ip6_src};
				static uint8_t ra_ethernet_addr[] = eth_allnodes;
				struct ip6_pkt *outpkt = (void *) radvd->packet;
				/* rewrite the destination MAC addr */
				memcpy(outpkt->ethh.ether_dhost, inpkt->ethh.ether_shost, ETH_ALEN);
				/* send the packet */
				send_advertisement(radvd, &dest, sizeof(dest));
				/* restore the destination multicast MAC addr */
				memcpy(outpkt->ethh.ether_dhost, &ra_ethernet_addr, ETH_ALEN);
			}
		}
	}
}

/* radvd daemon thread code */
static void *iothradvd_loop(void *vradvd) {
	struct iothradvd *radvd = vradvd;
	struct sockaddr_in6 allnodes = {
		.sin6_family = AF_INET6,
		.sin6_addr = ll_allnodes,
  };
	int fd = radvd->conn ? vde_datafd(radvd->conn) : radvd->sd;
  struct pollfd fds[] = {{fd, POLLIN, 0}};
  int poll_deadline = 0;
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  time_t nextperiod = now.tv_sec;
	if (radvd->period == 0)
		nextperiod = MAX_TIME;
	/* main loop, waiting for incoming packet (router solicitation)
	 * or the next second for periodic multicast adverisements */
  for (;;) {
    int pollrv = poll(fds, 1, poll_deadline);
    if (pollrv > 0)
      recv_solicitation(radvd);
    if (pollrv < 0)
      break;
    clock_gettime(CLOCK_REALTIME, &now);
    if (now.tv_sec >= nextperiod) {
      //printf("bc ra %lld %lld %lld\n", now.tv_sec, now.tv_nsec, nextperiod);
      send_advertisement(radvd, &allnodes, sizeof(allnodes));
      nextperiod = nextperiod + radvd->period;
    }
    poll_deadline = (1000000000L - now.tv_nsec) / 1000000;
  }
  return NULL;
}

static struct iothradvd *_iothradvd_start(
		struct ioth *stack, unsigned int ifindex,
		char *vnl, void *macaddr, int period,
    struct iothradata *data,
    struct iothraprefix *pdata, int npdata) {
	struct iothradvd *radvd = calloc(1, sizeof(*radvd));
	uint8_t mac[ETH_ALEN];
	if (radvd == NULL) goto err;
	radvd->period = period;
	radvd->sd = -1;
	int hoplimit = 255; // XXX
	FILE *f = open_memstream(&radvd->packet, &radvd->packetlen);
	if (f == NULL) goto errf;
	if (vnl == NULL) {
		/* libioth mode */
		struct ipv6_mreq mreq = {
			.ipv6mr_interface = ifindex,
			.ipv6mr_multiaddr = ll_allrouters,
		};
		radvd->sd = ioth_msocket(stack, AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		if (radvd->sd < 0)
			goto errf;
		ioth_setsockopt(radvd->sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hoplimit, sizeof(hoplimit));
		ioth_setsockopt(radvd->sd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
		if (ioth_linkgetaddr(stack, ifindex, mac) == 0)
			macaddr = mac;
	} else {
		/* VDE + IPv6 emulation mode */
		radvd->conn = vde_open(vnl, "radvd", NULL);
		if (radvd->conn == NULL)
			goto errf;
		/* define a random MAC address if macaddr == NULL */
		if (macaddr == NULL) {
			unsigned int oui;
			unsigned int nic;
			srand(time(NULL) + getpid());
			oui = (rand() & 0xfcffff) | 0x020000;
			nic = rand() & 0xffffff;
			mac[0] = oui >> 16;
			mac[1] = oui >> 8;
			mac[2] = oui;
			mac[3] = nic >> 16;
			mac[4] = nic >> 8;
			mac[5] = nic;
			macaddr = mac;
		}
		/* define the (emulated) link local IPv6 address */
		struct in6_addr ll_addr = {.s6_addr = {0xfe,0x80}};
		iothaddr_eui64(&ll_addr, macaddr);
		/* set up the packet */
		struct ip6_pkt pkt = {
			.ethh.ether_dhost = eth_allnodes,
			.ethh.ether_type = htons(0x86dd),
			.ipv6h.ip6_src = ll_addr,
			.ipv6h.ip6_dst = ll_allnodes,
			.ipv6h.ip6_plen = 0
		};
		memcpy(&pkt.ethh.ether_shost, macaddr, ETH_ALEN);
		pkt.ipv6h.ip6_vfc = 6 << 4;
		pkt.ipv6h.ip6_nxt = IPPROTO_ICMPV6;
		pkt.ipv6h.ip6_hlim = hoplimit;
		fwrite(&pkt, sizeof(pkt), 1, f);
	}
	/* set up the IMCPv6 packet */
	ra_addheader(f, data);
	for (int i = 0; i < npdata; i++)
		ra_addprefix(f, &pdata[i]);
	ra_addslla(f, macaddr);
	ra_addmtu(f, data->mtu);
	fclose(f);
	f = NULL;
	/* start the daemon thread */
	if (pthread_create(&radvd->tid, NULL, iothradvd_loop, radvd) == 0)
		return radvd;
errf:
	if (radvd->conn != NULL)
		vde_close(radvd->conn);
	if (radvd->sd >= 0) close(radvd->sd);
	if (f) fclose(f);
	if (radvd->packet) free(radvd->packet);
	free(radvd);
err:
	return NULL;
}

struct iothradvd *iothradvd_start(
		struct ioth *stack, unsigned int ifindex, int period,
		struct iothradata *data,
		struct iothraprefix *pdata, int npdata) {
	return _iothradvd_start(stack, ifindex, NULL, NULL, period, data, pdata, npdata);
}

struct iothradvd *iothradvd_vdestart(
		char *vnl, void *macaddr, int period,
		struct iothradata *data,
		struct iothraprefix *pdata, int npdata) {
	return _iothradvd_start(NULL, 0, vnl, macaddr, period, data, pdata, npdata);
}

void iothradvd_stop(struct iothradvd *radvd) {
	pthread_cancel(radvd->tid);
  pthread_join(radvd->tid, NULL);
	if (radvd->conn != NULL)
		vde_close(radvd->conn);
	if (radvd->sd >= 0)
		close(radvd->sd);
	if (radvd->packet != NULL)
		free(radvd->packet);
	free(radvd);

}
