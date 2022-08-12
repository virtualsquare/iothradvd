# iothradvd
A Router Advertisement Daemon for the Internet of Threads

`iothradvd` is a router advertisement daemon for IPv6. It listens for router
solicitation messages and sends router advertisements as described in "Neighbor
Discovery  for  IP Version 6 (IPv6)" (RFC 4861).
Hosts can automatically configure their addresses, prefixes and other parameters
using the values acquired by RA messages.

`iothradvd` is a _daemon_ in the Internet of Threads definition: given that the
process is a network node by its own, `iothradvd` runs as a thread.

## `libiothradvd`: the IoTh router advertisement daemon library.

The daemon is started using one of the following functions:

```C
struct iothradvd *iothradvd_start(
     struct ioth *stack, unsigned int ifindex, int period,
     struct iothradata *data,
     struct iothraprefix *pdata, int npdata);

struct iothradvd *iothradvd_vdestart(
     char *vnl, void *macaddr, int period,
     struct iothradata *data,
     struct iothraprefix *pdata, int npdata);
```

The former function, `iothradvd_start` uses `libioth`, while the latter, `iothradvd_vdestart`
is implemented using VDE and an emulation of IPv6.

`iothradvd_start` needs two specific arguments:

* `stack`: the ioth stack (see [libioth](https://github.com/virtualsquare/libioth)), the kernel
stack is used if this argument is NULL.

* `ifindex`: the interface index (see `if_nametoindex`(3) or `ioth_if_nametoindex`).

`iothradvd_vdestart` has two specific arguments:

* `vnl`: the virtual network locator.

* `macaddr`: the MAC address (six bytes).

The remaining arguments are common among the two implementations:

* `period`: iothradvd generates non solicited advertisement packets if not 0. The value is the period in
seconds between two consecutive unsolicited packets. If the value is 0 the daemon only replies
to router solicitation packets.

* `data`: data about the netowrk, a pointer to a `struct iothradata`

* `pdata`: data of prefixes, it is an array of `struct iothraprefix`

* `npdata`: is the number of elements in _pdata_

### `struct iothradata`:

```C
    struct iothradata {
      uint8_t curhoplimit;
      uint8_t flags;
      uint16_t router_lifetime;
      uint32_t reachable;
      uint32_t retransmit;
      uint32_t mtu;
   };
```
* `curhoplimit`: hoplimit for router advertisement packets.

* `flags`: it is a bit field. The value can be a bitwise-or combination of  `ND_RA_FLAG_MANAGED`, `ND_RA_FLAG_OTHER`,`ND_RA_FLAG_HOME_AGENT` and other values defined in RFC 4861 section 4.2 and further modifications.

* `router_lifetime`: It is the lifetime associated
with the default router in units of seconds (RFC 4861)

* `reachable`: it is the time, in milliseconds, that a node assumes a neighbor is
reachable after having received a reachability confirmation (RFC 4861).

* `retransmit`: it is the time, in milliseconds, between retransmitted Neighbor
Solicitation messages. (RFC 4861).

* `mtu`: it is the MTU advertised for the network.

### `struct iothraprefix`

```C
    struct iothraprefix {
      struct in6_addr prefix;
      uint8_t prefixlen;
      uint8_t flags;
      uint32_t valid_time;
      uint32_t preferred_time;
    };
```

* `prefix`: the IPv6 prefix to be advertised.

* `prefixlen`: the number of leading bits
in the Prefix that are valid.  The value ranges
from 0 to 128.

* `flags`: it is a bit field. The value can be a bitwise-or combination of `ND_OPT_PI_FLAG_ONLINK`,
`ND_OPT_PI_FLAG_AUTO` and `ND_OPT_PI_FLAG_RADDR` (RFC 4861 section 4,6,2 and further modification)

* `valid_time`: it is length of time in
seconds (relative to the time the packet is sent)
that the prefix is valid for the purpose of on-link
determination.  A value of all one bits
(0xffffffff) represents infinity. (RFC 4861)

* `preferred_time`: it is the length of time in
seconds (relative to the time the packet is sent)
that addresses generated from the prefix via
stateless address autoconfiguration remain
preferred.  A value of all one bits
(0xffffffff) represents infinity. (RFC 4861)

## iothradvd command

The program named `iothradvd` is router advertisement daemon implementation for IPv6 based on `libiothradvd`.
It listens to router solicitations and sends router advertisements as described in "Neighbor
Discovery  for  IP Version 6 (IPv6)" (RFC 4861)

* `iothradvd` can be used to test the library features (`libiothradvd`)
* its source code is a tutorial on how to use `libiothradvd`
* if can be used instead of `radvd`(8)

Command line syntax:
```
   iothradvd OPTIONS prefix <prefix> ....
```

Each prefix is defined as `addr/len/flags/valid/preferred`:

* `addr`: IPv6 addr
* `len` : prefix length
* `flags <flag codes>`: L=on link, A=autoconf, R=addr is router
* `valid`: valid lifetime (secs)
* `preferred`: preferred lifetime (secs)

Example: `fc01::/64/LA/86400/14400`

### Options

* `--stack|-s <ioth_stack_conf> or VNL`. it uses an ipv6 emulation if this is a VDE VNL.
* `--rcfile|-f <conffile>`
* `--daemon|-d`
* `--pidfile|-p <pidfile>`
* `--verbose|-v`
* `--period|-P <period in seconds>`
* `--iface|-i <interface>`     only for ioth stack,  default value vde0
* `--macaddr|-m <mac_address>`  only for vde emulation set the radvd MAC addr
* `--hoplimit|-H <current hop limit>`
* `--flags|-F <flag codes>`    M=managed, O=other H=home h=hiprio l=loprio P=proxy
* `--lifetime|-L <router lifetime>` secs
* `--reachable|-r <reachable time>` msecs
* `--retransmit|-R <retransmit time>` msecs
* `--mtu|-M <mtu>

### configuration file syntax

The configuration file loaded using the option `-f` or `--rcfile` has the following syntax:

* lines beginning by '#' are comments.
* the other lines have a tag and may have an argument if required by the tag.
The tags have the same name of the long options (`--something`) of the command line, their arguments
have the same syntax and meaning of each equivalent command line option.
Command line arguments have priority on the configuration file specifications:
if the same tag is specified as a command line option and in the configuration file, the value
in the command line is taken and the other ignored.
`prefix` is the only tag that can appear several times in the configuration file.

```
      stack      <ioth_stack_conf>
      prefix     <prefix specification: addr/len/flags/valid/preferred>
      daemon
      pidfile    <pidfile>
      verbose
      period     <period in seconds>
      iface      <interface>
      macaddr    <mac address
      hoplimit   <value of hop limit>
      flags      <flag codes>
      lifetime   <router lifetime in secs>
      reachable  <reachable time in msecs>
      retransmit <retransmit time in msec>
      mtu        <mtu>
```

## How to install

`iothradvd`  depends on the following libraries, that must be installed in advance:

* [libioth](https://github.com/virtualsquare/libioth)
* [vdeplug4](https://github.com/rd235/vdeplug4)
* [iothconf](https://github.com/virtualsquare/iothconf)

`iothradvd` uses the cmake building system.
```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```
