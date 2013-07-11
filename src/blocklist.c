/*
   Blocklist management

   (c) 2008 Jindrich Makovicka (makovick@gmail.com)

   This file is part of NFblock.

   NFblock is free software; you can redistribute it and/or modify
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

#include "blocklist.h"
#include "nfblockd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>

void
blocklist_init(blocklist_t *blocklist)
{
    blocklist->entries = NULL;
    blocklist->entries2 = NULL;
    blocklist->count = 0;
    blocklist->size = 0;
#ifndef LOWMEM
    blocklist->subentries = 0;
    blocklist->subcount = 0;
#endif
}

void
blocklist_append(blocklist_t *blocklist,
                 uint32_t ip_min, uint32_t ip_max,
                 const char *name, iconv_t ic)
{
    block_entry_t *e;
    block_entry2_t *e2;

    if (blocklist->size == blocklist->count) {
        blocklist->size += 16384;
        blocklist->entries = realloc(blocklist->entries, sizeof(block_entry_t) * blocklist->size);
        blocklist->entries2 = realloc(blocklist->entries2, sizeof(block_entry2_t) * blocklist->size);
        CHECK_OOM(blocklist->entries);
        CHECK_OOM(blocklist->entries2);
    }
    e = blocklist->entries + blocklist->count;
    e2 = blocklist->entries2 + blocklist->count;
    e->ip_min = ip_min;
    e->ip_max = ip_max;
#ifndef LOWMEM
    if (ic >= 0) {
        char buf2[MAX_LABEL_LENGTH];
        size_t insize, outsize;
        char *inb, *outb;
        int ret;

        insize = strlen(name);
        inb = (char *)name;
        outsize = MAX_LABEL_LENGTH - 1;
        outb = buf2;
        memset(buf2, 0, MAX_LABEL_LENGTH);
        ret = iconv(ic, &inb, &insize, &outb, &outsize);
        if (ret >= 0) {
            e2->name = strdup(buf2);
        } else {
            do_log(LOG_ERR, "Cannot convert string: %s", strerror(errno));
            e2->name = strdup("(conversion error)");
        }
    } else {
        e2->name = strdup(name);
    }
    e2->merged_idx = -1;
#endif
    e2->hits = 0;
    e2->lasttime = 0;
    blocklist->count++;
}

void
blocklist_clear(blocklist_t *blocklist, int start)
{
    int i;

    for (i = start; i < blocklist->count; i++)
#ifndef LOWMEM
        if (blocklist->entries2[i].name)
            free(blocklist->entries2[i].name);
#endif
    if (start == 0) {
        free(blocklist->entries);
        free(blocklist->entries2);
        blocklist->entries = NULL;
        blocklist->entries2 = NULL;
        blocklist->count = 0;
        blocklist->size = 0;
#ifndef LOWMEM
        if (blocklist->subentries) {
            for (i = 0; i < blocklist->subcount; i++)
                if (blocklist->subentries[i].name)
                    free(blocklist->subentries[i].name);
            free(blocklist->subentries);
            blocklist->subentries = 0;
        }
        blocklist->subcount = 0;
#endif
    } else {
        blocklist->size = blocklist->count = start;
        blocklist->entries = realloc(blocklist->entries,
                                     sizeof(block_entry_t) * blocklist->size);
        blocklist->entries2 = realloc(blocklist->entries2,
                                     sizeof(block_entry2_t) * blocklist->size);
        CHECK_OOM(blocklist->entries);
        CHECK_OOM(blocklist->entries2);
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

void
blocklist_sort(blocklist_t *blocklist)
{
    qsort(blocklist->entries, blocklist->count, sizeof(block_entry_t), block_entry_compare);
}

void
blocklist_trim(blocklist_t *blocklist)
{
    int i, j, k, merged = 0;

    if (blocklist->count == 0)
	return;

#ifndef LOWMEM
    /* pessimistic, will be reallocated later */
    blocklist->subentries = (block_sub_entry_t *)malloc(blocklist->count * sizeof(block_sub_entry_t));
    CHECK_OOM(blocklist->subentries);
    blocklist->subcount = 0;
#endif

    for (i = 0; i < blocklist->count; i++) {
        uint32_t ip_max;
        ip_max = blocklist->entries[i].ip_max;
        /* Look if the following entries can be merged with the
         * current one */
        for (j = i + 1; j < blocklist->count; j++) {
            if (blocklist->entries[j].ip_min > ip_max + 1)
                break;
            if (blocklist->entries[j].ip_max > ip_max)
                ip_max = blocklist->entries[j].ip_max;
        }
        if (j > i + 1) {
            uint32_t ip1, ip2;
            char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];
            char *tmp = malloc(32 * (j - i + 1) + 1);
            CHECK_OOM(tmp);
            /* List the merged entries */
            tmp[0] = 0;
            for (k = i; k < j; k++) {
                char tmp2[33];
                ip1 = htonl(blocklist->entries[k].ip_min);
                ip2 = htonl(blocklist->entries[k].ip_max);
                inet_ntop(AF_INET, &ip1, buf1, sizeof(buf1));
                inet_ntop(AF_INET, &ip2, buf2, sizeof(buf2));
                sprintf(tmp2, "%s-%s ", buf1, buf2);
                strcat(tmp, tmp2);
            }
            ip1 = htonl(blocklist->entries[i].ip_min);
            ip2 = htonl(ip_max);
            inet_ntop(AF_INET, &ip1, buf1, sizeof(buf1));
            inet_ntop(AF_INET, &ip2, buf2, sizeof(buf2));
            do_log(LOG_DEBUG, "Merging ranges: %sinto %s-%s", tmp, buf1, buf2);
            free(tmp);

#ifndef LOWMEM
            /* Copy the sub-entries and mark the unneeded entries */
            blocklist->entries2[i].merged_idx = blocklist->subcount;
            for (k = i; k < j; k++) {
                blocklist->subentries[blocklist->subcount].ip_min = blocklist->entries[k].ip_min;
                blocklist->subentries[blocklist->subcount].ip_max = blocklist->entries[k].ip_max;
                blocklist->subentries[blocklist->subcount].name = blocklist->entries2[k].name;
                blocklist->subcount++;
                if (k > i) blocklist->entries2[k].hits = -1;
            }
            blocklist->entries2[i].name = 0;
#else
            for (k = i + 1; k < j; k++)
                if (k > i) blocklist->entries2[k].hits = -1;
#endif
            /* Extend the range */
            blocklist->entries[i].ip_max = ip_max;
            merged += j - i - 1;
            i = j - 1;
        }
    }

    /* Squish the list */
    if (merged) {
        for (i = 0, j = 0; i < blocklist->count; i++) {
            if (blocklist->entries2[i].hits >= 0) {
                if (i != j) {
                    memcpy(blocklist->entries + j, blocklist->entries + i, sizeof(block_entry_t));
                    memcpy(blocklist->entries2 + j, blocklist->entries2 + i, sizeof(block_entry2_t));
                }
                j++;
            }
        }
        blocklist->count -= merged;
        do_log(LOG_DEBUG, "%d entries merged", merged);
    }

#ifndef LOWMEM
    if (blocklist->count) {
	blocklist->entries = realloc(blocklist->entries, blocklist->count * sizeof(block_entry_t));
        blocklist->entries2 = realloc(blocklist->entries2, blocklist->count * sizeof(block_entry2_t));
	CHECK_OOM(blocklist->entries);
	CHECK_OOM(blocklist->entries2);
    } else {
	free(blocklist->entries);
	free(blocklist->entries2);
	blocklist->entries = 0;
	blocklist->entries2 = 0;
    }
    if (blocklist->subcount) {
	blocklist->subentries = (block_sub_entry_t *)realloc(blocklist->subentries, blocklist->subcount * sizeof(block_sub_entry_t));
	CHECK_OOM(blocklist->subentries);
    } else {
	free(blocklist->subentries);
	blocklist->subentries = 0;
    }
#endif
}

#ifndef LOWMEM
static int
compare_hits(const void *p1, const void *p2)
{
    return (*(block_entry2_t **)p2)->hits - (*(block_entry2_t **)p1)->hits;
}
#endif

void
blocklist_stats(blocklist_t *blocklist)
{
    int i;
    long total = 0;

#ifndef LOWMEM
    block_entry2_t **sorted_entries2;
    int entry_count = 0;

    for (i = 0; i < blocklist->count; i++)
        if (blocklist->entries2[i].hits >= 1)
            entry_count++;

    sorted_entries2 = (block_entry2_t **)malloc(sizeof(block_entry2_t *) * entry_count);
    CHECK_OOM(sorted_entries2);
    for (i = 0, entry_count = 0; i < blocklist->count; i++) {
        if (blocklist->entries2[i].hits >= 1)
            sorted_entries2[entry_count++] = &blocklist->entries2[i];
    }
    qsort(sorted_entries2, entry_count, sizeof(block_entry2_t *), compare_hits);
#else
    int entry_count = blocklist->count;
#endif

    do_log(LOG_INFO, "Blocker hit statistic:");
    for (i = 0; i < entry_count; i++) {
#ifndef LOWMEM
        block_entry2_t *e2 = sorted_entries2[i];
        block_entry_t *e = &blocklist->entries[e2 - blocklist->entries2];
#else
        block_entry2_t *e2 = &blocklist->entries2[i];
        block_entry_t *e = &blocklist->entries[i];
#endif
        if (e2->hits >= 1) {
            uint32_t ip1, ip2;
            char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];
            ip1 = htonl(e->ip_min);
            ip2 = htonl(e->ip_max);
            inet_ntop(AF_INET, &ip1, buf1, sizeof(buf1));
            inet_ntop(AF_INET, &ip2, buf2, sizeof(buf2));
#ifndef LOWMEM
            if (e2->name) {
                do_log(LOG_INFO, "%s - %s-%s: %d", e2->name,
                       buf1, buf2, e2->hits);
            } else {
                int j, cnt;
                block_sub_entry_t *s;
                cnt = 0;
                for (j = e2->merged_idx; j < blocklist->subcount; j++) {
                    s = &blocklist->subentries[j];
                    if (s->ip_max > e->ip_max)
                        break;
                    cnt++;
                }
                s = &blocklist->subentries[e2->merged_idx];
                do_log(LOG_INFO, "%s [+%d] - %s-%s: %d", s->name, cnt - 1,
                       buf1, buf2, e2->hits);
            }
#else
            do_log(LOG_INFO, "%s-%s: %d", buf1, buf2, e2->hits);
#endif
            total += e2->hits;
        }
    }
    do_log(LOG_INFO, "%ld hits total", total);
#ifndef LOWMEM
    free(sorted_entries2);
#endif
}

#ifndef LOWMEM
block_entry2_t *
blocklist_find(blocklist_t *blocklist, uint32_t ip,
               const char **names, int max)
{
    block_entry_t e;
    block_entry_t *ret;
    block_entry2_t *ret2;
    int i, cnt;

    e.ip_min = e.ip_max = ip;
    ret = bsearch(&e, blocklist->entries, blocklist->count, sizeof(block_entry_t), block_key_compare);
    if (!ret)
        // entry not found
        return 0;

    ret2 = &blocklist->entries2[ret - blocklist->entries];
    if (!names)
        goto out;

    if (ret2->name) {
        // entry found, no subentries
        names[0] = ret2->name;
        names[1] = 0;
        goto out;
    }

    // scan the subentries
    cnt = 0;
    for (i = ret2->merged_idx; i < blocklist->subcount; i++) {
        block_sub_entry_t * e = &blocklist->subentries[i];
        if (e->ip_min > ret->ip_max)
            break;
        if (cnt >= max)
            break;
        if (e->ip_min <= ip && e->ip_max >= ip)
            names[cnt++] = e->name;
    }

    if (cnt == 0)
        do_log(LOG_ERR, "No sub-entries found, should not happen!");

    names[cnt] = 0;

out:
    return ret2;
}
#else
block_entry2_t *
blocklist_find(blocklist_t *blocklist, uint32_t ip,
               void *dummy1, int dummy2)
{
    block_entry_t e;
    block_entry_t *ret;

    e.ip_min = e.ip_max = ip;
    ret = bsearch(&e, blocklist->entries, blocklist->count, sizeof(block_entry_t), block_key_compare);

    if (!ret)
        // entry not found
        return 0;

    return &blocklist->entries2[ret - blocklist->entries];
}
#endif

void
blocklist_dump(blocklist_t *blocklist)
{
    int i;

    for (i = 0; i < blocklist->count; i++) {
        uint32_t ip1, ip2;
        char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];
        block_entry_t *e = &blocklist->entries[i];
#ifndef LOWMEM
        block_entry2_t *e2 = &blocklist->entries2[i];
#endif

        ip1 = htonl(e->ip_min);
        ip2 = htonl(e->ip_max);
        inet_ntop(AF_INET, &ip1, buf1, sizeof(buf1));
        inet_ntop(AF_INET, &ip2, buf2, sizeof(buf2));
#ifndef LOWMEM
        if (e2->name) {
            printf("%d - %s-%s - %s\n", i, buf1, buf2, e2->name);
        } else {
            int j;
            printf("%d - %s-%s is a composite range:\n", i, buf1, buf2);
            for (j = e2->merged_idx; j < blocklist->subcount; j++) {
                block_sub_entry_t *s = &blocklist->subentries[j];
                if (s->ip_min > e->ip_max) break;
                ip1 = htonl(s->ip_min);
                ip2 = htonl(s->ip_max);
                inet_ntop(AF_INET, &ip1, buf1, sizeof(buf1));
                inet_ntop(AF_INET, &ip2, buf2, sizeof(buf2));
                printf("  Sub-Range: %s-%s - %s\n", buf1, buf2, s->name);
                if (s->ip_max > e->ip_max) {
                    printf("  Partial overlap, should not happen!\n");
                }
            }
        }
#else
        printf("%d - %s-%s\n", i, buf1, buf2);
#endif
    }
}
