/*
   Blocklist management

   (c) 2008 Jindrich Makovicka (makovick@gmail.com)

   This file is part of NFblock.

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

#ifndef BLOCKLIST_H
#define BLOCKLIST_H

#include <inttypes.h>
#include <time.h>

/* iconv is not needed in LOWMEM mode (no strings handled) */
#ifndef LOWMEM
#include <iconv.h>
#else
typedef int iconv_t;
static inline iconv_t iconv_open(const char *tocode, const char *fromcode)
{
    return 0;
}
static inline int iconv_close(iconv_t cd)
{
    return 0;
}
#endif

#define MAX_LABEL_LENGTH 255

#ifndef LOWMEM
typedef struct
{
    uint32_t ip_min, ip_max;
    char *name;
} block_sub_entry_t;
#endif

typedef struct
{
    /* must start with sub-entry */
    uint32_t ip_min, ip_max;
#ifndef LOWMEM
    char *name;
#endif

    int hits;
#ifndef LOWMEM
    int merged_idx;
#endif
    time_t lasttime;
} block_entry_t;

typedef struct
{
    block_entry_t *entries;
    unsigned int count, size;

#ifndef LOWMEM
    block_sub_entry_t *subentries;
    unsigned int subcount;
#endif
} blocklist_t;

void blocklist_init(blocklist_t *blocklist);
void blocklist_append(blocklist_t *blocklist,
                      uint32_t ip_min, uint32_t ip_max,
                      const char *name, iconv_t ic);
void blocklist_clear(blocklist_t *blocklist, int start);
void blocklist_sort(blocklist_t *blocklist);
void blocklist_trim(blocklist_t *blocklist);
void blocklist_stats(blocklist_t *blocklist);
#ifndef LOWMEM
block_entry_t * blocklist_find(blocklist_t *blocklist, uint32_t ip,
                               block_sub_entry_t **sub, int max);
#else
block_entry_t * blocklist_find(blocklist_t *blocklist, uint32_t ip,
                               void *dummy1, int dummy2);
#endif
void blocklist_dump(blocklist_t *blocklist);

#endif
