/*
   Netfilter blocking daemon

   (c) 2011 Jindrich Makovicka (makovick@gmail.com)

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

/*
  Simple tester of the sort & trim functionality
  Scans whole IPv4 range, checks for false positives & negatives
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

#include "blocklist.h"
#include "parser.h"
#include "nfblockd.h"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

static blocklist_t blocklist;

void
do_log(int priority, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

#define MAX_RANGES 16

int64_t *bitfield;

int
main(int argc, char *argv[])
{
    uint64_t i, j;
    const char *sranges[MAX_RANGES + 1];

    blocklist_init(&blocklist);
    blocklist_clear(&blocklist, 0);
    load_list(&blocklist, "level1.gz", NULL);
    fprintf(stderr, "%d entries\n", blocklist.count);
/*
    load_list(&blocklist, "level2.gz", NULL);
    fprintf(stderr, "%d entries\n", blocklist.count);
    load_list(&blocklist, "level3.gz", NULL);
    fprintf(stderr, "%d entries\n", blocklist.count);
    load_list(&blocklist, "pt.gz", NULL);
    fprintf(stderr, "%d entries\n", blocklist.count);
*/
    bitfield = (int64_t *)malloc(0x100000000UL >> 3);
    fprintf(stderr, "%d entries\n", blocklist.count);

    memset(bitfield, 0, 0x100000000 >> 3);
    for (i = 0; i < blocklist.count; i++) {
        if ((i & 10000) == 0)
            fprintf(stderr, "entry %ld\n", i);
        for (j = blocklist.entries[i].ip_min; j <= blocklist.entries[i].ip_max; j++) {
            bitfield[j >> 6] |= (uint64_t)1 << (j & 0x3f);
        }
        blocklist.entries2[i].hits=rand();
    }

    blocklist_sort(&blocklist);
    blocklist_trim(&blocklist);
    blocklist_dump(&blocklist);

    fprintf(stderr, "%d entries after trim\n", blocklist.count);
    for (i = 0; i <= 0xffffffffULL; i++) {
        block_entry2_t * res;
        if ((i & 0xffffff) == 0)
            fprintf(stderr, "%08lx\n", i);
        res = blocklist_find(&blocklist, i, sranges, MAX_RANGES);
        if (res == NULL) {
            if ((bitfield[i >> 6] & ((uint64_t)1 << (i & 0x3f))) != 0)
                fprintf(stderr, "false negative! %08lx\n", i);
        } else {
            if ((bitfield[i >> 6] & ((uint64_t)1 << (i & 0x3f))) == 0)
                fprintf(stderr, "false positive! %08lx\n", i);
        }
    }

    blocklist_stats(&blocklist);
    return 0;
}
