/*
 *   iothradvd.c: router advertisement daemon for ioth
 *
 *   Copyright 2022 Renzo Davoli - Virtual Square Team
 *   University of Bologna - Italy
 *
 * iothradvd is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>. 
 *
 */

#define SPDX_LICENSE "SPDX-License-Identifier: GPL-2.0-or-later"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>

#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <iothconf.h>
#include <utils.h>
#include <iothradvd.h>

static int verbose;
static char *cwd;
static pid_t mypid;

static struct iothradvd *radvd;

#ifndef _GNU_SOURCE
static inline char *strchrnul(const char *s, int c) {
	while (*s && *s != c)
		s++;
	return (char *) s;
}
#endif

static void terminate(int signum) {
  pid_t pid = getpid();
  if (pid == mypid) {
    printlog(LOG_INFO, "(%d) leaving on signal %d", pid, signum);
		if (radvd != NULL)
			iothradvd_stop(radvd);
  }
	exit(0);
}

static void setsignals(void) {
  struct sigaction action = {
    .sa_handler = terminate
  };
  sigaction(SIGINT, &action, NULL);
  sigaction(SIGTERM, &action, NULL);
}

/* Main and command line args management */
void usage(char *progname)
{
	fprintf(stderr,"Usage: %s OPTIONS prefix <prefix> ....\n"
			"\tprefix : addr/len/flags/valid/preferred\n"
			"\tex:  fc01::/64/LA/86400/14400\n"
			"\t  addr : IPv6 addr\n"
			"\t  len : prefix length\n"
			"\t  flags <flag codes> : L=on link, A=autoconf, R=addr is router\n"
			"\t  valid : valid lifetime (secs)\n"
			"\t  preferred: preferred lifetime (secs)\n"
			"\n"
			"\tOPTIONS:\n"
			"\t--stack|-s <ioth_stack_conf> or VNL\n"
			"\t           (it uses an ipv6 emulation if this is a VDE VNL)\n"
			"\t--rcfile|-f <conffile>\n"
			"\t--daemon|-d\n"
			"\t--pidfile|-p <pidfile>\n"
			"\t--verbose|-v\n"
			"\t--period|-P <period in seconds>\n"
			"\t--iface|-i <interface>      (only for ioth stack,  default value vde0)\n"
			"\t--macaddr|-m <mac_address>  (only for vde emulation set the radvd MAC addr)\n"
			"\t--hoplimit|-H <current hop limit>\n"
			"\t--flags|-F <flag codes>     (M=managed, O=other H=home h=hiprio l=loprio P=proxy)\n"
			"\t--lifetime|-L <router lifetime> (secs)\n"
			"\t--reachable|-r <reachable time> (msecs)\n"
			"\t--retransmit|-R <retransmit time> (msecs)\n"
			"\t--mtu|-M <mtu>\n"
			"\t--help|-h\n",
		progname);
	exit(1);
}

static char *short_options = "hdvf:p:s:P:i:m:H:F:L:r:R:M:";
static struct option long_options[] = {
	{"help", 0, 0, 'h'},
	{"daemon", 0, 0, 'd'},
	{"verbose", 0, 0, 'v'},
	{"rcfile", 1, 0, 'f'},
	{"pidfile", 1, 0, 'p'},
	{"stack", 1, 0, 's'},
	{"period", 1, 0, 'P'},
	{"iface", 1, 0, 'i'},
	{"macaddr", 1, 0, 'm'},
	{"hoplimit", 1, 0,'H'},
	{"flags", 1, 0, 'F'},
	{"lifetime", 1, 0, 'L'},
	{"reachable", 1, 0, 'r'},
	{"retransmit", 1, 0, 'R'},
	{"mtu", 1, 0, 'M'},
	{0,0,0,0}
};

static char *arg_tags = "dvpsPimHFLrRM";
static union {
	struct {
		char *daemon;
		char *verbose;
		char *pidfile;
		char *stack;
		char *period;
		char *iface;
		char *macaddr;
		char *hoplimit;
		char *flags;
		char *lifetime;
		char *reachable;
		char *retransmit;
		char *mtu;
	};
	char *argv[sizeof(arg_tags)];
} args;

static inline int argindex(char tag) {
	return strchrnul(arg_tags, tag) - arg_tags;
}

typedef int extraparse(char *optname, char *value, void *arg);
int parsercfile(char *path, struct option *options, extraparse xp, void *arg) {
	int retvalue = 0;
	FILE *f = fopen(path, "r");
	if (f == NULL) return -1;
	char *line = NULL;
	size_t len;
	for (int lineno = 1; getline(&line, &len, f) > 0; lineno++) { //foreach line
		char *scan = line;
		while (*scan && strchr("\t ", *scan)) scan++; //ship heading spaces
		if (strchr("#\n", *scan)) continue; // comments and empty lines
		int len = strlen(scan);
		char optname[len], value[len];
		// parse the line
		*value = 0;
		/* optname <- the first alphanumeric field (%[a-zA-Z0-9])
			 value <- the remaining of the line not including \n (%[^\n])
			 and discard the \n (%*c) */
		if (sscanf (line, "%[a-zA-Z0-9] %[^\n]%*c", optname, value) > 0) {
			struct option *optscan;
			for (optscan = options; optscan->name; optscan++) // search tag
				if (strcmp(optscan->name, optname) == 0)
					break;
			int index; // index of short opt tag in arg_tags
			if (optscan->name == NULL ||
					arg_tags[index = strchrnul(arg_tags, optscan->val) - arg_tags] == '\0') {
				if (xp == NULL || xp(optname, value, arg) < 0) {
					fprintf(stderr,"%s (line %d): parameter error %s\n", path, lineno, optname);
					errno = EINVAL, retvalue |= -1;
				}
			} else if (args.argv[index] == NULL) // overwrite only if NULL
				args.argv[index] = *value ? strdup(value) : "";
		} else {
			fprintf(stderr,"%s (line %d): syntax error\n", path, lineno);
			errno = EINVAL, retvalue |= -1;
		}
	}
	fclose(f);
	if (line) free(line);
	return retvalue;
}

int prefixarg(char *optname, char *value, void *arg) {
	if (strcmp(optname, "prefix") == 0 && arg != NULL) {
		FILE *f = arg;
		char *pre = strdup(value);
		fwrite(&pre, sizeof(pre), 1, f);
		return 0;
	}
	return -1;
}

void parse_prefix(struct iothraprefix *pre, char *in) {
	char *str;
	char *saveptr;
	char *item;
	int i;
	pre->prefixlen = 64;
	pre->flags = 0;
	pre->valid_time = 0xffffffff;
	pre->preferred_time = 0xffffffff;
	for(str = in, i = 0; (item = strtok_r(str, "/", &saveptr)) != NULL; str = NULL, i++) {
		switch (i) {
			case 0: if (inet_pton(AF_INET6, item, &pre->prefix) != 1) {
								printlog(LOG_ERR, "prefix address syntax error %s", in);
								exit(1);
							};
							break;
			case 1: pre->prefixlen = strtol(item, NULL, 0); break;
			case 2: for (char *s = item; *s != '\0'; s++) {
								switch (*s) {
									case 'L': pre->flags |= ND_OPT_PI_FLAG_ONLINK; break;
									case 'A': pre->flags |= ND_OPT_PI_FLAG_AUTO; break;
									case 'R': pre->flags |= ND_OPT_PI_FLAG_RADDR; break;
									default: printlog(LOG_ERR, "prefix %s unknown flag %c", in, *s);
                 exit(1);
								}
							}
							break;
			case 3: pre->valid_time = strtol(item, NULL, 0); break;
			case 4: pre->preferred_time = strtol(item, NULL, 0); break;
			default: printlog(LOG_ERR, "prefix syntax error %s", in);
							 exit(1);
		}
	}
	if (i == 0) {
		 printlog(LOG_ERR, "prefix syntax error: address required");
		 exit(1);
	}
}

int main(int argc, char *argv[])
{
	char *progname = basename(argv[0]);
	char *rcfile = NULL;
	char **prefix_args = NULL;
	int option_index;
	while(1) {
		int c;
		if ((c = getopt_long (argc, argv, short_options,
						long_options, &option_index)) < 0)
			break;
		switch (c) {
			case 'f':
				rcfile = optarg;
				break;
			case -1:
			case '?':
			case 'h': usage(progname); break;
			default: {
								 int index = argindex(c);
								 if (args.argv[index] == NULL)
									 args.argv[index] = optarg ? optarg : "";
							 }
								break;
		}
	}
	if (argc == 1)
		usage(progname);

	prefix_args = argv + optind;

	if (rcfile) {
		char *buf = NULL;
		size_t buflen;
		FILE *f = (*prefix_args == NULL) ? open_memstream(&buf, &buflen) : NULL;
		if (parsercfile(rcfile, long_options, prefixarg, f) < 0) {
			fprintf(stderr, "configfile %s: %s\n", rcfile, strerror(errno));
			exit(1);
		}
		if (f) {
			char *null = NULL;
			fwrite(&null, sizeof(null), 1, f);
			fclose(f);
			prefix_args = (char **) buf;
		}
	}

	if (args.verbose) verbose = 1;

	startlog(progname, args.daemon != NULL);
	mypid = getpid();
	setsignals();
	/* saves current path in cwd, because otherwise with daemon() we
	 * forget it */
	if((cwd = getcwd(NULL, 0)) == NULL) {
		printlog(LOG_ERR, "getcwd: %s", strerror(errno));
		exit(1);
	}
	if (args.daemon && daemon(0, 0)) {
		printlog(LOG_ERR,"daemon: %s", strerror(errno));
		exit(1);
	}

	/* once here, we're sure we're the true process which will continue as a
	 * server: save PID file if needed */
	if(args.pidfile) save_pidfile(args.pidfile, cwd);

	uint8_t macaddr[ETH_ALEN];

	if (args.macaddr) {
		if (sscanf(args.macaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
					macaddr, macaddr + 1, macaddr + 2, macaddr + 3, macaddr + 4, macaddr + 5) < 6) {
			printlog(LOG_ERR, "macaddr: format error");
			exit(1);
		}
	}
	if (args.iface == NULL)
		args.iface = "vde0";

	struct iothradata radata = {0};

	if (args.hoplimit) radata.curhoplimit = strtol(args.hoplimit, NULL, 10);
	if (args.flags) {
		for (char *s = args.flags; *s != '\0'; s++) {
			switch (*s) {
				case 'M': radata.flags |= ND_RA_FLAG_MANAGED; break;
				case 'O': radata.flags |= ND_RA_FLAG_OTHER; break;
				case 'H': radata.flags |= ND_RA_FLAG_HOME_AGENT; break;
				case 'h': radata.flags |= 0x08; break; //RFC 4191
				case 'l': radata.flags |= 0x18; break;
				case 'P': radata.flags |= 0x04; break;
				default: printlog(LOG_ERR, "unknown flag %c", *s);
								 exit(1);
			}
		}
	}
	if (args.lifetime) radata.router_lifetime = strtol(args.lifetime, NULL, 10);
	if (args.reachable) radata.reachable = strtol(args.reachable, NULL, 10);
	if (args.retransmit) radata.retransmit = strtol(args.retransmit, NULL, 10);
	if (args.mtu) radata.mtu = strtol(args.mtu, NULL, 10);

	int rapdatalen = 0;
	while (prefix_args[rapdatalen] != 0)
		rapdatalen++;
	struct iothraprefix rapdata[rapdatalen];
	for (int i = 0; i < rapdatalen; i++)
		parse_prefix(&rapdata[i], prefix_args[i]);

	int period = 0;
	if (args.period) period = strtol(args.period, NULL, 10);

	if (args.stack != NULL && strstr(args.stack, "://")) { //
		radvd = iothradvd_vdestart(args.stack, (args.macaddr == NULL) ? NULL : macaddr,  
				period, &radata, rapdata, rapdatalen);
	} else {
		ioth_set_license(SPDX_LICENSE);
		struct ioth *stack = args.stack == NULL ? NULL : ioth_newstackc(args.stack);
		int ifindex = ioth_if_nametoindex(stack, args.iface);
		radvd = iothradvd_start(stack, ifindex, period, &radata, rapdata, rapdatalen);
	}

	if (radvd == NULL) {
		printlog(LOG_ERR, "starting error %s", strerror(errno));
		return 1;
	}

	for (;;)
		pause();
}
