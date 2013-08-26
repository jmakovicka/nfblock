NFblockD Netfilter blocking daemon
==================================

(c) 2007 Jindrich Makovicka <makovick@gmail.com>

Portions (c) 2004 Morpheus <ebutera@users.berlios.de>

Introduction
------------

NFblockD is a linux daemon filtering the IP connections according to a
supplied blocklist file. It understands the blocklists in the
following formats:

- IPFilter ascii files (used by eMule & derivatives, available at
  http://bluetack.co.uk). The input file can be optionally compressed
  using gzip.

- PeerGuardian ascii files, optionally gzipped.

- PeerGuardian binary files. Versions 1-3 are currently supported.

NFblockD can load more blocklist files if needed. The IP ranges will
be properly merged in that case.

Requirements
------------

1. iptables and kernel support for connection and state tracking (
   `ip_conntrack`, `ipt_state`) and `ipt_NFQUEUE` kernel
   modules (or built-in).

   At least kernel 2.6.14 together with the userspace libraries
   libnfnetlink and libnetfilter_queue are required to use the NFQUEUE
   interface.

   The following modules should suffice to run NFblockD:

   ```
   nfnetlink_queue         9280  1
   nfnetlink               4824  2 nfnetlink_queue
   ipt_NFQUEUE             1408  2
   ipt_state               1472  0
   ip_conntrack           40044  1 ipt_state
   iptable_filter          2176  1
   ip_tables              17600  3 ipt_NFQUEUE,ipt_state,iptable_filter
   ```

2. A valid `guarding.p2p/ipfilter.dat/p2p.p2b` host file(s).

   If you install the Debian package, the "Normal" IP blocklist from
   http://bluetack.co.uk will be downloaded and used by default. It
   can be changed by editing `BLOCKLIST_URL` in the configuration in
   `/etc/default/nfblockd` and running `dpkg-reconfigure nfblockd`.

   If the input file or files contain overlapping IP ranges, they will
   be merged automatically.

3. Minimum iptables knowledge, preferably an already working iptables
   setup :)

Setting up iptables
-------------------

NFblockD filter only packets that are NFQUEUEd with iptables. So it's
up to you to choose what traffic you want to be filtered.  For example
if you want NFblockD to filter all the new TCP connections that are
initiated from your box using NFQUEUE kernel interface:

```
iptables -A OUTPUT -p tcp -m state --state NEW -j NFQUEUE
```

NFQUEUE supports multiple queues (using `--queue-num` option), you
MUST specify it when launching NFblockD if you don't use the default
queue 0 using the `-q` command line option (`-q 0-65535`).  Running
two or more NFblockD instances to handle different queues was not
tested, do it at your own risk!

You might find out that using the blocklists as they come cripples
your connectivity too much. For example, some of the lists also
contain the private IP ranges, so it will cut you off completely if
you are on a LAN. It is also reasonable to punch some holes for the
"safe" protocols. To do this, you can define two additional chains,
one for the incoming traffic, and another one for outgoing.

This allows outgoing trafic to the local LAN, together with FTP,
http CVS and subversion:

```
iptables -N nfqout
iptables -A nfqout -o $IFACE -d 10.0.0.0/8 -j ACCEPT
iptables -A nfqout -o $IFACE -p tcp -m multiport \
         --dport ftp,http,https,svn,cvspserver -j ACCEPT
iptables -A nfqout -o $IFACE -j NFQUEUE
```

This allows incoming trafic from the local LAN:

```
iptables -N nfqin
iptables -A nfqin -i $IFACE -s 10.0.0.0/8 -j ACCEPT
iptables -A nfqin -i $IFACE -j NFQUEUE
```

**VERY IMPORTANT WARNING**

When a packet hits a `NFQUEUE` / `QUEUE` rule it will be accepted or
dropped by NFblockD (well it is what you want right? :P) so it will
NOT be checked by other rules that may follow in the chain. Basically,
the best practice is having the default `DROP` policy set, and then
replacing the `ACCEPT` targets where you'd like to have an additional
filtering with either `NFQUEUE` or `nfqin` / `nfqout`.

Setting up Shorewall
--------------------

Alternatively, when using Shorewall, NFQUEUE can be added to
`/etc/shorewall/blrules` as follows:

 ```
 # Always allow ssh 
 WHITELIST all all tcp ssh 
 
 # Allow outbound for particular protocols (eg. berlios.de is 
 # blocklisted) 
 WHITELIST fw,loc all tcp ftp,http,https,svn,git,domain,imaps,22100,7993 
 WHITELIST fw,loc all udp domain 
 
 # More whitelist rules may follow ... 
 
 # Check all new against the blocklist 
 NFQUEUE all all tcp 
 NFQUEUE all all udp 
 ```

Installation & Usage
--------------------

To build NFblockD from sources just do

```
make
```

in the directory where you extracted it. To build a Debian package, run

```
dpkg-buildpackage -rfakeroot
```

as usually.

To run the daemon, use

```
./nfblockd -d nipfilter.dat.gz
```

The daemon can be also controlled by the following signals:

To obtain stats (written to the syslog) about blocked ranges while
it's running:

```
kill -USR1 <pid>   # dumps the stats to syslog
```

To reload the blocklist, you can send the HUP signal:

```
kill -HUP <pid>    # reloads blocklist(s) and resets stats
```

D-Bus support
-------------

NFblockD is able to report filter hits via D-Bus interface
org.netfilter.nfblock . You can check the functionality by running

```
dbus-monitor --system
```

D-Bus can be eventually disabled using the `--no-dbus` option.

Credits
-------

- Morpheus (ebutera at users.berlios.de) for the original MoBlock and
  most of this README :)

- Crew of Bluetack for maintaining the blocklists themselves.

- João Valverde for the DBUS code.

- Santiago M. Mola for build fixes and cleanups.

