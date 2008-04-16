/* 
   NFblockD - Netfilter blocklist daemon
   
   (c) 2007 Jindrich Makovicka (makovick@gmail.com)

   Portions (c) 2004 Morpheus (ebutera@users.berlios.de)

   This file is part of NFblockD.

   NFblockD is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.
   
   NFblockD is distributed in the hope that it will be useful,
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
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <inttypes.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <poll.h>
#include <time.h>
#include <zlib.h>

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#define SRC_ADDR(pkt) (((struct iphdr *)pkt)->saddr)
#define DST_ADDR(pkt) (((struct iphdr *)pkt)->daddr)

#define CHUNK 1024
#define MIN_INTERVAL 60

typedef enum {
    CMD_NONE,
    CMD_DUMPSTATS,
    CMD_RELOAD,
    CMD_QUIT,
} command_t;

typedef struct
{
    uint32_t ip_min, ip_max;
    char *name;
    int hits;
    time_t lasttime;
} block_entry_t;

static block_entry_t *blocklist = NULL;
static unsigned int blocklist_count = 0, blocklist_size = 0;

int opt_daemon = 0, daemonized = 0;
int opt_verbose = 0;
int queue_num = 0;
uint32_t accept_mark = 0, reject_mark = 0;
char **blocklist_filenames;
volatile command_t command = CMD_NONE;
time_t curtime = 0;

#define IP_STRING_SIZE 16
#define MAX_LABEL_LENGTH 255

static void
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

static void
ip2str(char *dst, uint32_t ip)
{
    sprintf(dst, "%d.%d.%d.%d",
            (ip >> 24) & 0xff,
            (ip >> 16) & 0xff,
            (ip >> 8) & 0xff,
            ip & 0xff);
}

static void
blocklist_append(uint32_t ip_min, uint32_t ip_max, const char *name)
{
    block_entry_t *e;
    if (blocklist_size == blocklist_count) {
        blocklist_size += 16384;
        blocklist = realloc(blocklist, sizeof(block_entry_t) * blocklist_size);
    }
    e = blocklist + blocklist_count;
    e->ip_min = ip_min;
    e->ip_max = ip_max;
    e->name = strdup(name);
    e->hits = 0;
    e->lasttime = 0;
    blocklist_count++;
}

static void
blocklist_clear(int start)
{
    int i;

    for (i = start; i < blocklist_count; i++)
        free(blocklist[i].name);
    if (start == 0) {
        free(blocklist);
        blocklist = NULL;
        blocklist_count = 0;
        blocklist_size = 0;
    } else {
        blocklist_size = blocklist_count = start;
        blocklist = realloc(blocklist, sizeof(block_entry_t) * blocklist_size);
    }
}

static int
block_entry_compare(const void *a, const void *b)
{
    const block_entry_t *e1 = a;
    const block_entry_t *e2 = b;
    if (e1->ip_min < e2->ip_min) return -1;
    if (e1->ip_min > e2->ip_min) return 1;
    return 0;
}

static int
block_key_compare(const void *a, const void *b)
{
    const block_entry_t *key = a;
    const block_entry_t *entry = b;
    if (key->ip_max < entry->ip_min) return -1;
    if (key->ip_min > entry->ip_max) return 1;
    return 0;
}

static void
blocklist_sort()
{
    qsort(blocklist, blocklist_count, sizeof(block_entry_t), block_entry_compare);
}

static void
blocklist_trim()
{
    int i, j, k, merged = 0;

    for (i = 0; i < blocklist_count; i++) {
        uint32_t ip_max;
        ip_max = blocklist[i].ip_max;
        /* Look if the following entries can be merged with the
         * current one */
        for (j = i + 1; j < blocklist_count; j++) {
            if (blocklist[j].ip_min > ip_max + 1)
                break;
            if (blocklist[j].ip_max > ip_max)
                ip_max = blocklist[j].ip_max;
        }
        if (j > i + 1) {
            char buf1[IP_STRING_SIZE], buf2[IP_STRING_SIZE], dst[MAX_LABEL_LENGTH];
            char *tmp = malloc(32 * (j - i + 1) + 1);
            tmp[0] = 0;
            /* List the merged entries */
            dst[0] = 0;
            for (k = i; k < j; k++) {
                char tmp2[33];
                ip2str(buf1, blocklist[k].ip_min);
                ip2str(buf2, blocklist[k].ip_max);
                sprintf(tmp2, "%s-%s ", buf1, buf2);
                strcat(tmp, tmp2);
                strncat(dst, blocklist[k].name, MAX_LABEL_LENGTH - strlen(dst) - 1);
                if (k < j - 1)
                    strncat(dst, "; ", MAX_LABEL_LENGTH - strlen(dst) - 1);
            }
            ip2str(buf1, blocklist[i].ip_min);
            ip2str(buf2, ip_max);
            do_log(LOG_DEBUG, "Merging ranges: %sinto %s-%s (%s)", tmp, buf1, buf2, dst);
            free(tmp);

            /* Extend the range and mark the unneeded entries */
            blocklist[i].ip_max = ip_max;
            for (k = i; k < j; k++) {
                free(blocklist[k].name);
                if (k > i) blocklist[k].hits = -1;
            }
            blocklist[i].name = strdup(dst);
            merged += j - i - 1;
            i = j - 1;
        }
    }

    /* Squish the list */
    if (merged) {
        for (i = 0, j = 0; i < blocklist_count; i++) {
            if (blocklist[i].hits >= 0) {
                if (i != j)
                    memcpy(blocklist + j, blocklist + i, sizeof(block_entry_t));
                j++;
            }
        }
        blocklist_count -= merged;
        do_log(LOG_DEBUG, "%d entries merged", merged);
    }


    blocklist = realloc(blocklist, blocklist_count * sizeof(block_entry_t));
}

static void
blocklist_stats()
{
    int i, total = 0;

    do_log(LOG_INFO, "Blocker hit statistic:");
    for (i = 0; i < blocklist_count; i++) {
        if (blocklist[i].hits > 0) {
            char buf1[IP_STRING_SIZE], buf2[IP_STRING_SIZE];
            ip2str(buf1, blocklist[i].ip_min);
            ip2str(buf2, blocklist[i].ip_max);
            do_log(LOG_INFO, "%s - %s-%s: %d", blocklist[i].name,
                   buf1, buf2, blocklist[i].hits);
            total += blocklist[i].hits;
        }
    }
    do_log(LOG_INFO, "%d hits total", total);
}

static block_entry_t *
blocklist_find(uint32_t ip)
{
    block_entry_t e;

    e.ip_min = e.ip_max = ip;
    return bsearch(&e, blocklist, blocklist_count, sizeof(block_entry_t), block_key_compare);
}

/*
static void
blocklist_dump()
{
    int i;

    for (i = 0; i < blocklist_count; i++) {
        char buf1[IP_STRING_SIZE], buf2[IP_STRING_SIZE];
        ip2str(buf1, blocklist[i].ip_min);
        ip2str(buf2, blocklist[i].ip_max);
        printf("%d - %s-%s - %s\n", i, buf1, buf2, blocklist[i].name);
    }
}
*/

static void
strip_crlf(char *str)
{
    while (*str) {
        if (*str == '\r' || *str == '\n') {
            *str = 0;
            break;
        }
        str++;
    }
}

static inline uint32_t
assemble_ip(int i[4])
{
    return (i[0] << 24) + (i[1] << 16) + (i[2] << 8) + i[3];
}

typedef struct
{
    int compressed;
    FILE *f;
    int eos;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];
} stream_t;

static int
stream_open(stream_t *stream, const char *filename)
{
    int l = strlen(filename);
    if (l >= 3 && strcmp(filename + l - 3, ".gz") == 0) {
        stream->f = fopen(filename, "r");
        if (!stream->f)
            return -1;
        stream->compressed = 1;
        stream->strm.zalloc = Z_NULL;
        stream->strm.zfree = Z_NULL;
        stream->strm.opaque = Z_NULL;
        stream->strm.avail_in = 0;
        stream->strm.next_in = Z_NULL;
        if (inflateInit2(&stream->strm, 47) != Z_OK)
            return -1;
        stream->strm.avail_out = CHUNK;
        stream->strm.next_out = stream->out;
        stream->eos = 0;
    } else {
        stream->compressed = 0;
        stream->f = fopen(filename, "r");
        if (!stream->f)
            return -1;
    }
    return 0;
}

static int
stream_close(stream_t *stream)
{
    if (stream->compressed) {
        if (!stream->eos)
            inflateEnd(&stream->strm);
        if (fclose(stream->f) < 0)
            return -1;
    } else {
        if (fclose(stream->f) < 0)
            return -1;
    }
    return 0;
}

static char *
stream_getline(char *buf, int max, stream_t *stream)
{
    if (stream->compressed) {
        int ret, avail;
        unsigned char *ptr;
        if (!stream->eos && stream->strm.avail_out) {
            do {
                if (stream->strm.avail_in == 0) {
                    stream->strm.avail_in = fread(stream->in, 1, CHUNK, stream->f);
                    if (stream->strm.avail_in == 0) {
                        stream->eos = 1;
                        inflateEnd(&stream->strm);
                        break;
                    }
                    stream->strm.next_in = stream->in;
                }

                ret = inflate(&stream->strm, Z_NO_FLUSH);
                switch (ret) {
                case Z_STREAM_END:
                    stream->eos = 1;
                    inflateEnd(&stream->strm);
                    goto out;
                case Z_NEED_DICT:
                    ret = Z_DATA_ERROR;     /* and fall through */
                case Z_DATA_ERROR:
                case Z_MEM_ERROR:
                    stream->eos = 1;
                    inflateEnd(&stream->strm);
                    goto out;
                default:
                    break;
                }
            } while (stream->strm.avail_out);
        }
        
    out:        

        avail = CHUNK - stream->strm.avail_out;
        ptr = memchr(stream->out, '\n', avail);
        // handle lines is longer than the maximum
        if (!ptr && avail > max - 1)
            ptr = stream->out + max - 1;
        // handle missing LF at the end of file
        if (!ptr && avail && stream->eos)
            ptr = stream->out + avail - 1;
        // now, ptr should point to the last character copied, if there is any
        if (ptr) {
            int copied = ptr - stream->out + 1;
            if (copied >= max - 1)
                copied = max - 1;
            memcpy(buf, stream->out, copied);
            buf[copied] = 0;

            memmove(stream->out, stream->out + copied, avail - copied);
            stream->strm.avail_out += copied;
            stream->strm.next_out -= copied;
            return buf;
        }
        return NULL;
    } else {
        return fgets(buf, max, stream->f);
    }
}

static int
loadlist_dat(char *filename)
{
    stream_t s;
    char buf[MAX_LABEL_LENGTH], name[MAX_LABEL_LENGTH];
    int n, ip1[4], ip2[4], dummy;
    int total, ok;

    if (stream_open(&s, filename) < 0) {
        do_log(LOG_INFO, "Error opening %s.", filename);
        return -1;
    }

    total = ok = 0;
    while (stream_getline(buf, MAX_LABEL_LENGTH, &s)) {
        if (buf[0] == '#')
            continue;

        strip_crlf(buf);
        total++;
        if (ok == 0 && total > 100) {
            stream_close(&s);
            return -1;
        }

        memset(name, 0, sizeof(name));
        n = sscanf(buf, "%d.%d.%d.%d - %d.%d.%d.%d , %d , %199c",
                   &ip1[0], &ip1[1], &ip1[2], &ip1[3],
                   &ip2[0], &ip2[1], &ip2[2], &ip2[3],
                   &dummy, name);
        if (n != 10) continue;

        blocklist_append(assemble_ip(ip1), assemble_ip(ip2), name);
        ok++;
    }
    stream_close(&s);

    if (ok == 0) return -1;

    return 0;
}

static int
loadlist_p2p(char *filename)
{
    stream_t s;
    char buf[MAX_LABEL_LENGTH], name[MAX_LABEL_LENGTH];
    int n, ip1[4], ip2[4];
    int total, ok;

    if (stream_open(&s, filename) < 0) {
        do_log(LOG_INFO, "Error opening %s.", filename);
        return -1;
    }

    total = ok = 0;
    while (stream_getline(buf, MAX_LABEL_LENGTH, &s)) {
        strip_crlf(buf);
        total++;
        if (ok == 0 && total > 100) {
            stream_close(&s);
            return -1;
        }

        memset(name, 0, sizeof(name));
        n = sscanf(buf, "%199[^:]:%d.%d.%d.%d-%d.%d.%d.%d",
                   name,
                   &ip1[0], &ip1[1], &ip1[2], &ip1[3],
                   &ip2[0], &ip2[1], &ip2[2], &ip2[3]);
        if (n != 9) continue;

        blocklist_append(assemble_ip(ip1), assemble_ip(ip2), name);
        ok++;
    }
    stream_close(&s);

    if (ok == 0) return -1;

    return 0;
}

static int
read_cstr(char *buf, int maxsize, FILE *f)
{
    int c, n = 0;
    for (;;) {
        c = fgetc(f);
        if (c < 0) {
            buf[n++] = 0;
            return -1;
        }
        buf[n++] = c;
        if (c == 0)
            break;
        if (n == maxsize)
            return n + 1;
    }
    return n;
}

static int
loadlist_p2b(char *filename)
{
    FILE *f;
    uint8_t header[8];
    int version, n, i, nlabels = 0;
    uint32_t cnt, ip1, ip2, idx;
    char **labels = NULL;
    int ret = -1;

    f = fopen(filename, "r");
    if (!f) {
        do_log(LOG_INFO, "Error opening %s.", filename);
        return -1;
    }

    n = fread(header, 1, 8, f);
    if (n != 8)
        goto err;

    if (header[0] != 0xff
        || header[1] != 0xff
        || header[2] != 0xff
        || header[3] != 0xff
        || header[4] != 'P'
        || header[5] != '2'
        || header[6] != 'B')
    {
        goto err;
    }

    version = header[7];

    switch (version) {
    case 1:
    case 2:
        for (;;) {
            char buf[MAX_LABEL_LENGTH];
            uint32_t ip1, ip2;
            n = read_cstr(buf, MAX_LABEL_LENGTH, f);
            if (n < 0 || n > MAX_LABEL_LENGTH) {
                do_log(LOG_ERR, "P2B: Error reading label");
                break;
            }
            n = fread(&ip1, 1, 4, f);
            if (n != 4) {
                do_log(LOG_ERR, "P2B: Error reading range start");
                break;
            }
            n = fread(&ip2, 1, 4, f);
            if (n != 4) {
                do_log(LOG_ERR, "P2B: Error reading range end");
                break;
            }
            blocklist_append(ntohl(ip1), ntohl(ip2), buf);
        }
        break;
    case 3:
        n = fread(&cnt, 1, 4, f);
        if (n != 4)
            goto err;
        nlabels = ntohl(cnt);
        labels = (char**)malloc(sizeof(char*) * nlabels);
        if (!labels)
            goto err;
        for (i = 0; i < nlabels; i++)
            labels[i] = NULL;
        for (i = 0; i < nlabels; i++) {
            char buf[MAX_LABEL_LENGTH];
            n = read_cstr(buf, MAX_LABEL_LENGTH, f);
            if (n < 0 || n > MAX_LABEL_LENGTH) {
                do_log(LOG_ERR, "P2B3: Error reading label");
                goto err;
            }
            labels[i] = strdup(buf);
        }

        n = fread(&cnt, 1, 4, f);
        if (n != 4)
            break;
        cnt = ntohl(cnt);
        for (i = 0; i < cnt; i++) {
            n = fread(&idx, 1, 4, f);
            if (n != 4 || ntohl(idx) > nlabels) {
                do_log(LOG_ERR, "P2B3: Error reading label index");
                goto err;
            }
            n = fread(&ip1, 1, 4, f);
            if (n != 4) {
                do_log(LOG_ERR, "P2B3: Error reading range start");
                goto err;
            }
            n = fread(&ip2, 1, 4, f);
            if (n != 4) {
                do_log(LOG_ERR, "P2B3: Error reading range end");
                goto err;
            }
            blocklist_append(ntohl(ip1), ntohl(ip2), labels[ntohl(idx)]);
        }
        break;
    default:
        do_log(LOG_INFO, "Unknown P2B version: %d", version);
        goto err;
    }

    ret = 0;

err:
    if (labels) {
        for (i = 0; i < nlabels; i++)
            if (labels[i])
                free(labels[i]);
        free(labels);
    }
    fclose(f);
    return ret;
}

static int
load_list(char *filename)
{
    int prevcount;
    
    prevcount = blocklist_count;
    if (loadlist_p2b(filename) == 0) {
        do_log(LOG_DEBUG, "PeerGuardian Binary: %d entries loaded", blocklist_count - prevcount);
        return 0;
    }
    blocklist_clear(prevcount);

    prevcount = blocklist_count;
    if (loadlist_dat(filename) == 0) {
        do_log(LOG_DEBUG, "IPFilter: %d entries loaded", blocklist_count - prevcount);
        return 0;
    }
    blocklist_clear(prevcount);

    prevcount = blocklist_count;
    if (loadlist_p2p(filename) == 0) {
        do_log(LOG_DEBUG, "PeerGuardian Ascii: %d entries loaded", blocklist_count - prevcount);
        return 0;
    }
    blocklist_clear(prevcount);

    return -1;
}

static int
load_all_lists()
{
    int i, ret = 0;
    
    for (i = 0; blocklist_filenames[i]; i++) {
        if (load_list(blocklist_filenames[i])) {
            do_log(LOG_ERR, "Error loading %s", blocklist_filenames[i]);
            ret = -1;
        }
    }
    blocklist_sort();
    blocklist_trim();
    return ret;
}

static int
nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
           struct nfq_data *nfa, void *data)
{
    int id = 0, status = 0;
    struct nfqnl_msg_packet_hdr *ph;
    char *payload;
    block_entry_t *src, *dst;
    char buf1[IP_STRING_SIZE], buf2[IP_STRING_SIZE];

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
        nfq_get_payload(nfa, &payload);

        switch (ph->hook) {
        case NF_IP_LOCAL_IN:
            src = blocklist_find(ntohl(SRC_ADDR(payload)));
            if (src) {
                // we drop the packet instead of rejecting
                // we don't want the other host to know we are alive
                status = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                ip2str(buf1, ntohl(SRC_ADDR(payload)));
                src->hits++;
                if (src->lasttime < curtime - MIN_INTERVAL)
                    do_log(LOG_NOTICE, "Blocked IN: %s, hits: %d, SRC: %s",
                           src->name, src->hits, buf1);
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
            dst = blocklist_find(ntohl(DST_ADDR(payload)));
            if (dst) {
                if (likely(reject_mark)) {
                    // we set the user-defined reject_mark and set NF_REPEAT verdict
                    // it's up to other iptables rules to decide what to do with this marked packet
                    status = nfq_set_verdict_mark(qh, id, NF_REPEAT, reject_mark, 0, NULL);
                } else {
                    status = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                }
                ip2str(buf1, ntohl(DST_ADDR(payload)));
                dst->hits++;
                if (dst->lasttime < curtime - MIN_INTERVAL)
                    do_log(LOG_NOTICE, "Blocked OUT: %s, hits: %d, DST: %s",
                           dst->name, dst->hits, buf1);
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
            src = blocklist_find(ntohl(SRC_ADDR(payload)));
            dst = blocklist_find(ntohl(DST_ADDR(payload)));
            if (dst || src) {
                int lasttime = 0;
                if (likely(reject_mark)) {
                    // we set the user-defined reject_mark and set NF_REPEAT verdict
                    // it's up to other iptables rules to decide what to do with this marked packet
                    status = nfq_set_verdict_mark(qh, id, NF_REPEAT, reject_mark, 0, NULL);
                } else {
                    status = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                }
                ip2str(buf1, ntohl(SRC_ADDR(payload)));
                ip2str(buf2, ntohl(DST_ADDR(payload)));
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
                if (lasttime < curtime - MIN_INTERVAL)
                    do_log(LOG_NOTICE, "Blocked FWD: %s->%s, hits: %d,%d, SRC: %s, DST: %s",
                           src ? src->name : "(unknown)", dst ? dst->name : "(unknown)",
                           src ? src->hits : 0, dst ? dst->hits : 0, buf1, buf2);
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
nfqueue_loop ()
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd, rv;
    char buf[2048];
    struct pollfd fds[1];

    h = nfq_open();
    if (!h) {
        do_log(LOG_ERR, "Error during nfq_open(): %s", strerror(errno));
        return -1;
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        do_log(LOG_ERR, "Error during nfq_bind_pf(): %s", strerror(errno));
        nfq_close(h);
        return -1;
    }

    do_log(LOG_INFO, "NFQUEUE: binding to queue %d", queue_num);
    qh = nfq_create_queue(h, queue_num, &nfqueue_cb, NULL);
    if (!qh) {
        do_log(LOG_ERR, "error during nfq_create_queue(): %s", strerror(errno));
        nfq_close(h);
        return -1;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 21) < 0) {
        do_log(LOG_ERR, "can't set packet_copy mode: %s", strerror(errno));
        nfq_destroy_queue(qh);
        nfq_close(h);
        return -1;
    }

    nh = nfq_nfnlh(h);
    fd = nfnl_fd(nh);

    for (;;) {
        fds[0].fd = fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        rv = poll(fds, 1, 5000);

        curtime = time(NULL);

        if (rv < 0)
            goto out;
        if (rv > 0) {
            rv = recv(fd, buf, sizeof(buf), 0);
            if (rv < 0)
                goto out;
            if (rv >= 0)
                nfq_handle_packet(h, buf, rv);
        }

        if (unlikely (command != CMD_NONE)) {
            switch (command) {
            case CMD_DUMPSTATS:
                blocklist_stats();
                break;
            case CMD_RELOAD:
                blocklist_stats();
                if (load_all_lists() < 0)
                    do_log(LOG_ERR, "Cannot load the blocklist");
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
    do_log(LOG_INFO, "NFQUEUE: unbinding from queue 0");
    nfq_destroy_queue(qh);
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        do_log(LOG_ERR, "Error during nfq_unbind_pf(): %s", strerror(errno));
    }
    nfq_close(h);
    return 0;
}

static void
sighandler(int sig)
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
    default:
        break;
    }
}

static int
install_sighandler()
{
    struct sigaction sa;

    sa.sa_handler = sighandler;
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        perror("Error setting signal handler for SIGUSR1\n");
        return -1;
    }
    if ( sigaction(SIGHUP, &sa, NULL) < 0 ) {
        perror("Error setting signal handler for SIGHUP\n");
        return -1;
    }
    if ( sigaction(SIGTERM, &sa, NULL) < 0 ) {
        perror("Error setting signal handler for SIGTERM\n");
        return -1;
    }
    if ( sigaction(SIGINT, &sa, NULL) < 0 ) {
        perror("Error setting signal handler for SIGINT\n");
        return -1;
    }
    return 0;
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

static void
print_usage()
{
    fprintf(stderr, "nfblockd " VERSION " (c) 2007 Jindrich Makovicka\n");
    fprintf(stderr, "Syntax: nfblockd -d [-a MARK] [-r MARK] [-q 0-65535] BLOCKLIST...\n\n");
    fprintf(stderr, "        -d            Run as daemon\n");
    fprintf(stderr, "        -v            Verbose output\n");
    fprintf(stderr, "        -q 0-65535    NFQUEUE number, as specified in --queue-num with iptables\n");
    fprintf(stderr, "        -a MARK       32-bit mark to place on ACCEPTED packets\n");
    fprintf(stderr, "        -r MARK       32-bit mark to place on REJECTED packets\n");
    fprintf(stderr, "\n");
}

int
main(int argc, char *argv[])
{
    int opt, i;

    while ((opt = getopt(argc, argv, "q:a:r:dv")) != -1) {
        switch (opt) {
        case 'd':
            opt_daemon = 1;
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
        case 'v':
            opt_verbose++;
            break;
        }
    }

    if (queue_num < 0 || queue_num > 65535 || argc <= optind) {
        print_usage();
        exit(1);
    }

    blocklist_filenames = (char**)malloc(sizeof(char*) * (argc - optind + 1));
    for (i = 0; i < argc - optind; i++)
        blocklist_filenames[i] = argv[optind + i];
    blocklist_filenames[i] = 0;

    if (load_all_lists() < 0) {
        do_log(LOG_ERR, "Cannot load the blocklist");
        return -1;
    }

    if (opt_daemon) {
        daemonize();
        openlog("nfblockd", 0, LOG_DAEMON);
    }
    if (install_sighandler() != 0)
        return -1;

    do_log(LOG_INFO, "Started");
    do_log(LOG_INFO, "Blocklist has %d entries", blocklist_count);
    nfqueue_loop();
    blocklist_stats();
    if (opt_daemon) {
        closelog();
    }
    blocklist_clear(0);
    free(blocklist_filenames);
    return 0;
}
