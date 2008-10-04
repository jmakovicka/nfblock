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

void
blocklist_init(blocklist_t *blocklist)
{
    blocklist->entries = NULL;
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
    if (blocklist->size == blocklist->count) {
        blocklist->size += 16384;
        blocklist->entries = realloc(blocklist->entries, sizeof(block_entry_t) * blocklist->size);
        CHECK_OOM(blocklist->entries);
    }
    e = blocklist->entries + blocklist->count;
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
            e->name = strdup(buf2);
        } else {
            do_log(LOG_ERR, "Cannot convert string: %s", strerror(errno));
            e->name = strdup("(conversion error)");
        }
    } else {
        e->name = strdup(name);
    }
    e->merged_idx = -1;
#endif
    e->hits = 0;
    e->lasttime = 0;
    blocklist->count++;
}

void
blocklist_clear(blocklist_t *blocklist, int start)
{
    int i;

    for (i = start; i < blocklist->count; i++)
#ifndef LOWMEM
        if (blocklist->entries[i].name)
            free(blocklist->entries[i].name);
#endif
    if (start == 0) {
        free(blocklist->entries);
        blocklist->entries = NULL;
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
        CHECK_OOM(blocklist->entries);
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
            char buf1[IP_STRING_SIZE], buf2[IP_STRING_SIZE];
            char *tmp = malloc(32 * (j - i + 1) + 1);
            CHECK_OOM(tmp);
            /* List the merged entries */
            tmp[0] = 0;
            for (k = i; k < j; k++) {
                char tmp2[33];
                ip2str(buf1, blocklist->entries[k].ip_min);
                ip2str(buf2, blocklist->entries[k].ip_max);
                sprintf(tmp2, "%s-%s ", buf1, buf2);
                strcat(tmp, tmp2);
            }
            ip2str(buf1, blocklist->entries[i].ip_min);
            ip2str(buf2, ip_max);
            do_log(LOG_DEBUG, "Merging ranges: %sinto %s-%s", tmp, buf1, buf2);
            free(tmp);

#ifndef LOWMEM
            /* Copy the sub-entries and mark the unneeded entries */
            blocklist->entries[i].merged_idx = blocklist->subcount;
            for (k = i; k < j; k++) {
                blocklist->subentries[blocklist->subcount].ip_min = blocklist->entries[k].ip_min;
                blocklist->subentries[blocklist->subcount].ip_max = blocklist->entries[k].ip_max;
                blocklist->subentries[blocklist->subcount].name = blocklist->entries[k].name;
                blocklist->subcount++;
                if (k > i) blocklist->entries[k].hits = -1;
            }
            blocklist->entries[i].name = 0;
#else
            for (k = i + 1; k < j; k++)
                if (k > i) blocklist->entries[k].hits = -1;
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
            if (blocklist->entries[i].hits >= 0) {
                if (i != j)
                    memcpy(blocklist->entries + j, blocklist->entries + i, sizeof(block_entry_t));
                j++;
            }
        }
        blocklist->count -= merged;
        do_log(LOG_DEBUG, "%d entries merged", merged);
    }

#ifndef LOWMEM
    if (blocklist->count) {
	blocklist->entries = realloc(blocklist->entries, blocklist->count * sizeof(block_entry_t));
	CHECK_OOM(blocklist->entries);
    } else {
	free(blocklist->entries);
	blocklist->entries = 0;
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

void
blocklist_stats(blocklist_t *blocklist)
{
    int i, total = 0;

    do_log(LOG_INFO, "Blocker hit statistic:");
    for (i = 0; i < blocklist->count; i++) {
        block_entry_t *e = &blocklist->entries[i];
        if (e->hits >= 1) {
            char buf1[IP_STRING_SIZE], buf2[IP_STRING_SIZE];
            ip2str(buf1, e->ip_min);
            ip2str(buf2, e->ip_max);
#ifndef LOWMEM
            if (e->name) {
                do_log(LOG_INFO, "%s - %s-%s: %d", e->name,
                       buf1, buf2, e->hits);
            } else {
                int j, cnt;
                block_sub_entry_t *s;
                cnt = 0;
                for (j = e->merged_idx; j < blocklist->subcount; j++) {
                    s = &blocklist->subentries[j];
                    if (s->ip_max > e->ip_max)
                        break;
                    cnt++;
                }
                s = &blocklist->subentries[e->merged_idx];
                do_log(LOG_INFO, "%s [+%d] - %s-%s: %d", s->name, cnt - 1,
                       buf1, buf2, e->hits);
            }
#else
            do_log(LOG_INFO, "%s-%s: %d", buf1, buf2, e->hits);
#endif
            total += e->hits;
        }
    }
    do_log(LOG_INFO, "%d hits total", total);
}

#ifndef LOWMEM
block_entry_t *
blocklist_find(blocklist_t *blocklist, uint32_t ip,
               block_sub_entry_t **sub, int max)
{
    block_entry_t e;
    block_entry_t *ret;
    int i, cnt;

    e.ip_min = e.ip_max = ip;
    ret = bsearch(&e, blocklist->entries, blocklist->count, sizeof(block_entry_t), block_key_compare);

    if (!ret || !sub)
        // entry not found
        return ret;

    if (ret->name) {
        // entry found, no subentries
        sub[0] = (block_sub_entry_t *)ret;
        sub[1] = 0;
        return ret;
    }

    // scan the subentries
    cnt = 0;
    for (i = ret->merged_idx; i < blocklist->subcount; i++) {
        block_sub_entry_t * e = &blocklist->subentries[i];
        if (cnt >= max)
            break;
        if (e->ip_min <= ip && e->ip_max >= ip)
            sub[cnt++] = e;
    }
    sub[cnt] = 0;
    return ret;
}
#else
block_entry_t *
blocklist_find(blocklist_t *blocklist, uint32_t ip,
               void *dummy1, int dummy2)
{
    block_entry_t e;

    e.ip_min = e.ip_max = ip;
    return bsearch(&e, blocklist->entries, blocklist->count, sizeof(block_entry_t), block_key_compare);
}
#endif

void
blocklist_dump(blocklist_t *blocklist)
{
    int i;

    for (i = 0; i < blocklist->count; i++) {
        char buf1[IP_STRING_SIZE], buf2[IP_STRING_SIZE];
        block_entry_t *e = &blocklist->entries[i];

        ip2str(buf1, e->ip_min);
        ip2str(buf2, e->ip_max);
#ifndef LOWMEM
        if (e->name) {
            printf("%d - %s-%s - %s\n", i, buf1, buf2, e->name);
        } else {
            int j;
            printf("%d - %s-%s is a composite range:\n", i, buf1, buf2);
            for (j = e->merged_idx; j < blocklist->subcount; j++) {
                block_sub_entry_t *s = &blocklist->subentries[j];
                if (s->ip_max > s->ip_max) break;
                ip2str(buf1, s->ip_min);
                ip2str(buf2, s->ip_max);
                printf("  Sub-Range: %s-%s - %s\n", buf1, buf2, s->name);
            }
        }
#else
        printf("%d - %s-%s\n", i, buf1, buf2);
#endif
    }
}
