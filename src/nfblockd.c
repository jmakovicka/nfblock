/*
   Netfilter blocking daemon

   (c) 2008 Jindrich Makovicka (makovick@gmail.com)

   Portions (c) 2004 Morpheus (ebutera@users.berlios.de)

   This file is part of NFblock.

   NFblock is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   NFblock is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Emacs; see the file COPYING.  If not, write to
   the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <syslog.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <poll.h>

#ifdef HAVE_DBUS
#include <dlfcn.h>
#include "dbus.h"
#endif

#include "blocklist.h"
#include "parser.h"
#include "nfblockd.h"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define SRC_ADDR(pkt) (((struct iphdr *)pkt)->saddr)
#define DST_ADDR(pkt) (((struct iphdr *)pkt)->daddr)

#define MIN_INTERVAL 60

typedef enum {
    CMD_NONE,
    CMD_DUMPSTATS,
    CMD_RELOAD,
    CMD_QUIT,
} command_t;

static blocklist_t blocklist;

static int opt_daemon = 0, daemonized = 0;
static int benchmark = 0;
static int opt_verbose = 0;
static int queue_num = 0;
static int use_syslog = 1;
static uint32_t accept_mark = 0, reject_mark = 0;
static const char *pidfile_name = "/var/run/nfblockd.pid";

static const char *current_charset = 0;

static int blockfile_count = 0;
static const char **blocklist_filenames = 0;
static const char **blocklist_charsets = 0;

static volatile command_t command = CMD_NONE;
static time_t curtime = 0;
static FILE* pidfile = NULL;

struct nfq_handle *nfqueue_h = 0;
struct nfq_q_handle *nfqueue_qh = 0;

void
do_log(int priority, const char *format, ...)
{
    va_list ap;

    if (priority == LOG_DEBUG && opt_verbose < 1)
        goto noprint;

    if (!daemonized) {
        va_start(ap, format);
        vfprintf(stderr, format, ap);
        fprintf(stderr, "\n");
        va_end(ap);
    }
noprint:
    if (opt_daemon) {
        va_start(ap, format);
        vsyslog(priority, format, ap);
        va_end(ap);
    }
}

#ifdef HAVE_DBUS

static int use_dbus = 1;
static void *dbus_lh = NULL;

static nfblock_dbus_init_t nfblock_dbus_init = NULL;
static nfblock_dbus_send_blocked_t nfblock_dbus_send_blocked = NULL;

#define do_dlsym(symbol)                                                \
    do {                                                                \
        symbol = dlsym(dbus_lh, # symbol);                              \
        err = dlerror();                                                \
        if (err) {                                                      \
            do_log(LOG_ERR, "Cannot get symbol %s: %s", # symbol, err); \
            goto out_err;                                               \
        }                                                               \
    } while (0)

static int
open_dbus()
{
    char *err;

    dbus_lh = dlopen(PLUGINDIR "/dbus.so", RTLD_NOW);
    if (!dbus_lh) {
        do_log(LOG_ERR, "dlopen() failed: %s", dlerror());
        return -1;
    }
    dlerror(); // clear the error flag

    do_dlsym(nfblock_dbus_init);
    do_dlsym(nfblock_dbus_send_blocked);

    return 0;

out_err:
    dlclose(dbus_lh);
    dbus_lh = 0;
    return -1;
}

static int
close_dbus()
{
    int ret = 0;

    if (dbus_lh) {
        ret = dlclose(dbus_lh);
        dbus_lh = 0;
    }

    return ret;
}

#endif

void
ip2str(char *dst, uint32_t ip)
{
    sprintf(dst, "%d.%d.%d.%d",
            (ip >> 24) & 0xff,
            (ip >> 16) & 0xff,
            (ip >> 8) & 0xff,
            ip & 0xff);
}


static int
load_all_lists()
{
    int i, ret = 0;

    blocklist_clear(&blocklist, 0);
    for (i = 0; i < blockfile_count; i++) {
        if (load_list(&blocklist, blocklist_filenames[i], blocklist_charsets[i])) {
            do_log(LOG_ERR, "Error loading %s", blocklist_filenames[i]);
            ret = -1;
        }
    }
    blocklist_sort(&blocklist);
    blocklist_trim(&blocklist);
    return ret;
}

#define MAX_RANGES 16
static int
nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
           struct nfq_data *nfa, void *data)
{
    int id = 0, status = 0;
    struct nfqnl_msg_packet_hdr *ph;
    char *payload;
    block_entry_t *src, *dst;
    uint32_t ip_src, ip_dst;
    char buf1[IP_STRING_SIZE], buf2[IP_STRING_SIZE];
#ifndef LOWMEM
    block_sub_entry_t *sranges[MAX_RANGES + 1], *dranges[MAX_RANGES + 1];
#else
    /* dummy variables */
    static void *sranges = 0, *dranges = 0;
#endif

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
        nfq_get_payload(nfa, &payload);

        switch (ph->hook) {
        case NF_IP_LOCAL_IN:
            ip_src = ntohl(SRC_ADDR(payload));
            src = blocklist_find(&blocklist, ip_src, sranges, MAX_RANGES);
            if (src) {
                // we drop the packet instead of rejecting
                // we don't want the other host to know we are alive
                status = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                src->hits++;
                if (src->lasttime < curtime - MIN_INTERVAL) {
                    ip2str(buf1, ip_src);
#ifdef HAVE_DBUS
                    if (use_dbus) {
                        nfblock_dbus_send_blocked(do_log, curtime, LOG_NF_IN,
                                                  reject_mark ? false : true,
                                                  buf1, sranges, src->hits);
                    }
#endif
                    if (use_syslog) {
#ifndef LOWMEM
                        do_log(LOG_NOTICE, "Blocked IN: %s, hits: %d, SRC: %s",
                               sranges[0]->name, src->hits, buf1);
#else
                        do_log(LOG_NOTICE, "Blocked IN: hits: %d, SRC: %s",
                               src->hits, buf1);
#endif
                    }
                }
                src->lasttime = curtime;
            } else if (unlikely(accept_mark)) {
                // we set the user-defined accept_mark and set NF_REPEAT verdict
                // it's up to other iptables rules to decide what to do with this marked packet
                status = nfq_set_verdict_mark(qh, id, NF_REPEAT, accept_mark, 0, NULL);
            } else {
                // no accept_mark, just NF_ACCEPT the packet
                status = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
            }
            break;
        case NF_IP_LOCAL_OUT:
            ip_dst = ntohl(DST_ADDR(payload));
            dst = blocklist_find(&blocklist, ip_dst, dranges, MAX_RANGES);
            if (dst) {
                if (likely(reject_mark)) {
                    // we set the user-defined reject_mark and set NF_REPEAT verdict
                    // it's up to other iptables rules to decide what to do with this marked packet
                    status = nfq_set_verdict_mark(qh, id, NF_REPEAT, reject_mark, 0, NULL);
                } else {
                    status = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                }
                dst->hits++;
                if (dst->lasttime < curtime - MIN_INTERVAL) {
                    ip2str(buf1, ip_dst);
#ifdef HAVE_DBUS
                    if (use_dbus) {
                        nfblock_dbus_send_blocked(do_log, curtime, LOG_NF_OUT,
                                                  reject_mark ? false : true,
                                                  buf1, dranges, dst->hits);
                    }
#endif
                    if (use_syslog) {
#ifndef LOWMEM
                        do_log(LOG_NOTICE, "Blocked OUT: %s, hits: %d, DST: %s",
                                        dranges[0]->name, dst->hits, buf1);
#else
                        do_log(LOG_NOTICE, "Blocked OUT: %s, hits: %d, DST: %s",
                               dst->hits, buf1);
#endif
                    }
                }
                dst->lasttime = curtime;
            } else if (unlikely(accept_mark)) {
                // we set the user-defined accept_mark and set NF_REPEAT verdict
                // it's up to other iptables rules to decide what to do with this marked packet
                status = nfq_set_verdict_mark(qh, id, NF_REPEAT, accept_mark, 0, NULL);
            } else {
                // no accept_mark, just NF_ACCEPT the packet
                status = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
            }
            break;
        case NF_IP_FORWARD:
            ip_src = ntohl(SRC_ADDR(payload));
            ip_dst = ntohl(DST_ADDR(payload));
            src = blocklist_find(&blocklist, ip_src, sranges, MAX_RANGES);
            dst = blocklist_find(&blocklist, ip_dst, dranges, MAX_RANGES);
            if (dst || src) {
                int lasttime = 0;
                if (likely(reject_mark)) {
                    // we set the user-defined reject_mark and set NF_REPEAT verdict
                    // it's up to other iptables rules to decide what to do with this marked packet
                    status = nfq_set_verdict_mark(qh, id, NF_REPEAT, reject_mark, 0, NULL);
                } else {
                    status = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                }
                if (src) {
                    src->hits++;
                    lasttime = src->lasttime;
                    src->lasttime = curtime;
                }
                if (dst) {
                    dst->hits++;
                    if (dst->lasttime > lasttime)
                        lasttime = dst->lasttime;
                    dst->lasttime = curtime;
                }
                if (lasttime < curtime - MIN_INTERVAL) {
                    ip2str(buf1, ip_src);
                    ip2str(buf2, ip_dst);
#ifdef HAVE_DBUS
                    if (use_dbus) {
                        if (src) {
                            nfblock_dbus_send_blocked(do_log, curtime, LOG_NF_IN,
                                                      reject_mark ? false : true,
                                                      buf1, sranges, src->hits);
                        }
                        if (dst) {
                            nfblock_dbus_send_blocked(do_log, curtime, LOG_NF_OUT, reject_mark ? false : true,
                                                      buf2, dranges, dst->hits);
                        }
/*
                        nfblock_dbus_send_signal_nfq(do_log, curtime, LOG_NF_FWD, reject_mark ? NFBP_ACTION_MARK : NFBP_ACTION_DROP,
                                                     FMT_ADDR_RANGES_HITS, ip_src, src ? sranges : NULL, src ? src->hits : 0,
                                                     FMT_ADDR_RANGES_HITS, ip_dst, dst ? dranges : NULL, dst ? dst->hits : 0,
                                                     (char *)NULL);
*/
                    }
#endif
                    if (use_syslog) {

#ifndef LOWMEM
                        do_log(LOG_NOTICE, "Blocked FWD: %s->%s, hits: %d,%d, SRC: %s, DST: %s",
                               src ? sranges[0]->name : "(unknown)", dst ? dranges[0]->name : "(unknown)",
                               src ? src->hits : 0, dst ? dst->hits : 0, buf1, buf2);
#else
                        do_log(LOG_NOTICE, "Blocked FWD: hits: %d,%d, SRC: %s, DST: %s",
                               src ? src->hits : 0, dst ? dst->hits : 0, buf1, buf2);
#endif
                    }
                }
            } else if ( unlikely(accept_mark) ) {
                // we set the user-defined accept_mark and set NF_REPEAT verdict
                // it's up to other iptables rules to decide what to do with this marked packet
                status = nfq_set_verdict_mark(qh, id, NF_REPEAT, accept_mark, 0, NULL);
            } else {
                // no accept_mark, just NF_ACCEPT the packet
                status = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
            }
            break;
        default:
            do_log(LOG_NOTICE, "Not NF_LOCAL_IN/OUT/FORWARD packet!");
            break;
        }
    } else {
        do_log(LOG_ERR, "NFQUEUE: can't get msg packet header.");
        return 1;               // from nfqueue source: 0 = ok, >0 = soft error, <0 hard error
    }
    return 0;
}

static int
nfqueue_bind()
{
    nfqueue_h = nfq_open();
    if (!nfqueue_h) {
        do_log(LOG_ERR, "Error during nfq_open(): %s", strerror(errno));
        return -1;
    }

    if (nfq_bind_pf(nfqueue_h, AF_INET) < 0) {
        do_log(LOG_ERR, "Error during nfq_bind_pf(): %s", strerror(errno));
        nfq_close(nfqueue_h);
        return -1;
    }

    do_log(LOG_INFO, "NFQUEUE: binding to queue %d", queue_num);
    nfqueue_qh = nfq_create_queue(nfqueue_h, queue_num, &nfqueue_cb, NULL);
    if (!nfqueue_qh) {
        do_log(LOG_ERR, "error during nfq_create_queue(): %s", strerror(errno));
        nfq_close(nfqueue_h);
        return -1;
    }

    if (nfq_set_mode(nfqueue_qh, NFQNL_COPY_PACKET, 21) < 0) {
        do_log(LOG_ERR, "can't set packet_copy mode: %s", strerror(errno));
        nfq_destroy_queue(nfqueue_qh);
        nfq_close(nfqueue_h);
        return -1;
    }
    return 0;
}

static void
nfqueue_unbind()
{
    if (!nfqueue_h)
        return;

    do_log(LOG_INFO, "NFQUEUE: unbinding from queue 0");
    nfq_destroy_queue(nfqueue_qh);
    if (nfq_unbind_pf(nfqueue_h, AF_INET) < 0) {
        do_log(LOG_ERR, "Error during nfq_unbind_pf(): %s", strerror(errno));
    }
    nfq_close(nfqueue_h);
}

static int
nfqueue_loop ()
{
    struct nfnl_handle *nh;
    int fd, rv;
    char buf[2048];
    struct pollfd fds[1];

    if (nfqueue_bind() < 0)
        return -1;

    nh = nfq_nfnlh(nfqueue_h);
    fd = nfnl_fd(nh);

    for (;;) {
        fds[0].fd = fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        rv = poll(fds, 1, 5000);

        curtime = time(NULL);

        if (rv < 0) {
            if (errno == EINTR)
                continue;
            do_log(LOG_ERR, "Error waiting for socket: %s", strerror(errno));
            goto out;
        }
        if (rv > 0) {
            rv = recv(fd, buf, sizeof(buf), 0);
            if (rv < 0) {
                if (errno == EINTR)
                    continue;
                do_log(LOG_ERR, "Error reading from socket: %s", strerror(errno));
                goto out;
            }
            if (rv >= 0)
                nfq_handle_packet(nfqueue_h, buf, rv);
        }

        if (unlikely (command != CMD_NONE)) {
            switch (command) {
            case CMD_DUMPSTATS:
                blocklist_stats(&blocklist);
                break;
            case CMD_RELOAD:
                blocklist_stats(&blocklist);
                if (load_all_lists() < 0)
                    do_log(LOG_ERR, "Cannot load the blocklist");
                do_log(LOG_INFO, "Blocklist reloaded");
                break;
            case CMD_QUIT:
                goto out;
            default:
                break;
            }
            command = CMD_NONE;
        }
    }
out:
    nfqueue_unbind();
    return 0;
}

static void
sighandler(int sig, siginfo_t *info, void *context)
{
    switch (sig) {
    case SIGUSR1:
        command = CMD_DUMPSTATS;
        break;
    case SIGHUP:
        command = CMD_RELOAD;
        break;
    case SIGTERM:
    case SIGINT:
        command = CMD_QUIT;
        break;
    case SIGSEGV:
        nfqueue_unbind();
        abort();
        break;
    default:
        break;
    }
}

static int
install_sighandler()
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sighandler;
    sa.sa_flags = SA_RESTART | SA_SIGINFO;

    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        perror("Error setting signal handler for SIGUSR1\n");
        return -1;
    }
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        perror("Error setting signal handler for SIGHUP\n");
        return -1;
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("Error setting signal handler for SIGTERM\n");
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        perror("Error setting signal handler for SIGINT\n");
        return -1;
    }
    if (sigaction(SIGSEGV, &sa, NULL) < 0) {
        perror("Error setting signal handler for SIGABRT\n");
        return -1;
    }
    return 0;
}

static FILE *
create_pidfile(const char *name)
{
    FILE *f;

    f = fopen(name, "w");
    if (f == NULL){
        fprintf(stderr, "Unable to create PID file %s: %s\n", name, strerror(errno));
        return NULL;
    }

    /* this works even if pidfile is stale after daemon is sigkilled */
    if (lockf(fileno(f), F_TLOCK, 0) == -1){
        fprintf(stderr, "Unable to set exclusive lock for pidfile %s: %s\n", name, strerror(errno));
        return NULL;
    }

    fprintf(f, "%d\n", getpid());
    fflush(f);

    /* leave fd open as long as daemon is running */
    /* this is useful for example so that inotify can catch a file
     * closed event even if daemon is killed */
    return f;
}


static void
daemonize() {
    /* Fork off and have parent exit. */
    switch (fork()) {
    case -1:
        perror("fork");
        exit(1);

    case 0:
        break;

    default:
        exit(0);
    }

    /* detach from the controlling terminal */

    setsid();

    close(fileno(stdin));
    close(fileno(stdout));
    close(fileno(stderr));
    daemonized = 1;
}

static int64_t
ustime()
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

#if RAND_MAX < 65536
#error RAND_MAX needs to be at least 2^16
#endif
#define ITER 10000000
static void
do_benchmark()
{
    int i;
    int64_t start, end;

    start = ustime();
    for (i = 0; i < ITER; i++) {
        uint32_t ip;
        ip = (uint32_t)random() ^ ((uint32_t)random() << 16);
        blocklist_find(&blocklist, ip, 0, 0);
    }
    end = ustime();

    fprintf(stderr, "%" PRIi64 " matches per second.\n", ((int64_t)1000000) * ITER / (end - start));
}

static void
print_usage()
{
    fprintf(stderr, "nfblockd " VERSION " (c) 2008 Jindrich Makovicka\n");
    fprintf(stderr, "Syntax: nfblockd -d [-a MARK] [-r MARK] [-q 0-65535] BLOCKLIST...\n\n");
    fprintf(stderr, "        -d            Run as daemon\n");
#ifndef LOWMEM
    fprintf(stderr, "        -c            Blocklist file charset (for all following filenames)\n");
#endif
    fprintf(stderr, "        -f            Blocklist file name\n");
    fprintf(stderr, "        -p NAME       Use a pidfile named NAME\n");
    fprintf(stderr, "        -v            Verbose output\n");
    fprintf(stderr, "        -b            Benchmark IP matches per second\n");
    fprintf(stderr, "        -q 0-65535    NFQUEUE number, as specified in --queue-num with iptables\n");
    fprintf(stderr, "        -a MARK       32-bit mark to place on ACCEPTED packets\n");
    fprintf(stderr, "        -r MARK       32-bit mark to place on REJECTED packets\n");
    fprintf(stderr, "        --no-syslog   Disable hit logging to the system log\n");
#ifdef HAVE_DBUS
    fprintf(stderr, "        --no-dbus     Disable D-Bus support for hit reporting\n");
#endif
    fprintf(stderr, "\n");
}

enum long_option
{
    OPTION_NO_SYSLOG = CHAR_MAX + 1,
    OPTION_NO_DBUS
};

static struct option const long_options[] = {
    {"no-syslog", no_argument, NULL, OPTION_NO_SYSLOG},
#ifdef HAVE_DBUS
    {"no-dbus", no_argument, NULL, OPTION_NO_DBUS},
#endif
    {0, 0, 0, 0}
};

void
add_blocklist(const char *name, const char *charset)
{
    blocklist_filenames = (const char**)realloc(blocklist_filenames, sizeof(const char*) * (blockfile_count + 1));
    CHECK_OOM(blocklist_filenames);
    blocklist_charsets = (const char**)realloc(blocklist_charsets, sizeof(const char*) * (blockfile_count + 1));
    CHECK_OOM(blocklist_charsets);
    blocklist_filenames[blockfile_count] = name;
    blocklist_charsets[blockfile_count] = charset;
    blockfile_count++;
}

int
main(int argc, char *argv[])
{
    int opt, i;

    while ((opt = getopt_long(argc, argv, "q:a:r:dbp:f:v"
#ifndef LOWMEM
                              "c:"
#endif
                              , long_options, NULL)) != -1) {
        switch (opt) {
        case 'd':
            opt_daemon = 1;
            break;
        case 'b':
            benchmark = 1;
            break;
        case 'q':
            queue_num = atoi(optarg);
            break;
        case 'r':
            reject_mark = htonl((uint32_t)atoi(optarg));
            break;
        case 'a':
            accept_mark = htonl((uint32_t)atoi(optarg));
            break;
        case 'p':
            pidfile_name = optarg;
            break;
#ifndef LOWMEM
        case 'c':
            current_charset = optarg;
            break;
#endif
        case 'f':
            add_blocklist(optarg, current_charset);
            break;
        case 'v':
            opt_verbose++;
            break;
        case OPTION_NO_SYSLOG:
            use_syslog = 0;
            break;
#ifdef HAVE_DBUS
        case OPTION_NO_DBUS:
            use_dbus = 0;
            break;
#endif
        }
    }

    if (queue_num < 0 || queue_num > 65535) {
        print_usage();
        exit(1);
    }

    for (i = 0; i < argc - optind; i++)
        add_blocklist(argv[optind + i], current_charset);

    if (blockfile_count == 0) {
        print_usage();
        exit(1);
    }

    blocklist_init(&blocklist);

    if (load_all_lists() < 0) {
        do_log(LOG_ERR, "Cannot load the blocklist");
        return -1;
    }

    if (benchmark) {
        do_benchmark();
        goto out;
    }

    if (opt_daemon) {
        daemonize();
        openlog("nfblockd", 0, LOG_DAEMON);
    }

#ifdef HAVE_DBUS
    if (use_dbus) {
        if (open_dbus() < 0) {
            do_log(LOG_ERR, "Cannot load D-Bus plugin");
            use_dbus = 0;
        }
    }

    if (use_dbus) {
        if (nfblock_dbus_init(do_log) < 0) {
            do_log(LOG_INFO, "Cannot initialize D-Bus");
            use_dbus = 0;
        }
    }
#endif

    if (install_sighandler() != 0)
        return -1;

    pidfile = create_pidfile(pidfile_name);
    if (!pidfile)
        return -1;

    do_log(LOG_INFO, "Started");
    do_log(LOG_INFO, "Blocklist has %d entries", blocklist.count);
    nfqueue_loop();
    blocklist_stats(&blocklist);

    if (opt_daemon) {
        closelog();
    }

out:

#ifdef HAVE_DBUS
    if (use_dbus)
        close_dbus();
#endif

    blocklist_clear(&blocklist, 0);
    free(blocklist_filenames);
    free(blocklist_charsets);

    if (pidfile) {
        fclose(pidfile);
        unlink(pidfile_name);
    }

    return 0;
}
