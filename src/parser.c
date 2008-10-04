/*
   Blocklist parser

   (c) 2008 Jindrich Makovicka (makovick@gmail.com)

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

#include <stdlib.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>

#include "parser.h"
#include "stream.h"

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

static int
loadlist_dat(blocklist_t *blocklist, const char *filename, const char *charset)
{
    stream_t s;
    char buf[MAX_LABEL_LENGTH], name[MAX_LABEL_LENGTH];
    int n, ip1[4], ip2[4], dummy;
    int total, ok;
    int ret = -1;
    iconv_t ic;

    if (stream_open(&s, filename) < 0) {
        do_log(LOG_INFO, "Error opening %s.", filename);
        return -1;
    }

    ic = iconv_open("UTF-8", charset);
    if (ic < 0) {
        do_log(LOG_INFO, "Cannot initialize charset conversion: %s", strerror(errno));
        goto err;
    }

    total = ok = 0;
    while (stream_getline(buf, MAX_LABEL_LENGTH, &s)) {
        if (buf[0] == '#')
            continue;

        strip_crlf(buf);
        total++;
        if (ok == 0 && total > 100) {
            stream_close(&s);
            goto err;
        }

        memset(name, 0, sizeof(name));
        n = sscanf(buf, "%d.%d.%d.%d - %d.%d.%d.%d , %d , %199c",
                   &ip1[0], &ip1[1], &ip1[2], &ip1[3],
                   &ip2[0], &ip2[1], &ip2[2], &ip2[3],
                   &dummy, name);
        if (n != 10) continue;
        blocklist_append(blocklist, assemble_ip(ip1), assemble_ip(ip2), name, ic);
        ok++;
    }
    stream_close(&s);

    if (ok == 0) goto err;

    ret = 0;

err:
    if (ic)
        iconv_close(ic);

    return ret;
}

static int
loadlist_p2p(blocklist_t *blocklist, const char *filename, const char *charset)
{
    stream_t s;
    char buf[MAX_LABEL_LENGTH], name[MAX_LABEL_LENGTH];
    int n, ip1[4], ip2[4];
    int total, ok;
    int ret = -1;
    iconv_t ic;

    if (stream_open(&s, filename) < 0) {
        do_log(LOG_INFO, "Error opening %s.", filename);
        return -1;
    }

    ic = iconv_open("UTF-8", charset);
    if (ic < 0) {
        do_log(LOG_INFO, "Cannot initialize charset conversion: %s", strerror(errno));
        goto err;
    }

    total = ok = 0;
    while (stream_getline(buf, MAX_LABEL_LENGTH, &s)) {
        strip_crlf(buf);
        total++;
        if (ok == 0 && total > 100) {
            stream_close(&s);
            goto err;
        }

        memset(name, 0, sizeof(name));
        n = sscanf(buf, "%199[^:]:%d.%d.%d.%d-%d.%d.%d.%d",
                   name,
                   &ip1[0], &ip1[1], &ip1[2], &ip1[3],
                   &ip2[0], &ip2[1], &ip2[2], &ip2[3]);
        if (n != 9) continue;

        blocklist_append(blocklist, assemble_ip(ip1), assemble_ip(ip2), name, ic);
        ok++;
    }
    stream_close(&s);

    if (ok == 0) goto err;

    ret = 0;

err:
    if (ic)
        iconv_close(ic);

    return ret;
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
loadlist_p2b(blocklist_t *blocklist, const char *filename)
{
    FILE *f;
    uint8_t header[8];
    int version, n, i, nlabels = 0;
    uint32_t cnt, ip1, ip2, idx;
#ifndef LOWMEM
    char **labels = NULL;
#endif
    int ret = -1;
    iconv_t ic = (iconv_t) -1;

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
        ic = iconv_open("UTF-8", "ISO8859-1");
        break;
    case 2:
    case 3:
        ic = iconv_open("UTF-8", "UTF-8");
        break;
    default:
        do_log(LOG_INFO, "Unknown P2B version: %d", version);
        goto err;
    }

    if (ic < 0) {
        do_log(LOG_INFO, "Cannot initialize charset conversion: %s", strerror(errno));
        goto err;
    }

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
            blocklist_append(blocklist, ntohl(ip1), ntohl(ip2), buf, ic);
        }
        break;
    case 3:
        n = fread(&cnt, 1, 4, f);
        if (n != 4)
            goto err;
        nlabels = ntohl(cnt);
#ifndef LOWMEM
        labels = (char**)malloc(sizeof(char*) * nlabels);
        if (!labels) {
            do_log(LOG_ERR, "P2B: Out of memory");
            goto err;
        }
        for (i = 0; i < nlabels; i++)
            labels[i] = NULL;
#endif
        for (i = 0; i < nlabels; i++) {
            char buf[MAX_LABEL_LENGTH];
            n = read_cstr(buf, MAX_LABEL_LENGTH, f);
            if (n < 0 || n > MAX_LABEL_LENGTH) {
                do_log(LOG_ERR, "P2B3: Error reading label");
                goto err;
            }
#ifndef LOWMEM
            labels[i] = strdup(buf);
#endif
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
#ifndef LOWMEM
            blocklist_append(blocklist, ntohl(ip1), ntohl(ip2), labels[ntohl(idx)], ic);
#else
            blocklist_append(blocklist, ntohl(ip1), ntohl(ip2), NULL, ic);
#endif
        }
        break;
    }

    ret = 0;

err:
#ifndef LOWMEM
    if (labels) {
        for (i = 0; i < nlabels; i++)
            if (labels[i])
                free(labels[i]);
        free(labels);
    }
#endif
    fclose(f);
    if (ic)
        iconv_close(ic);
    return ret;
}

int
load_list(blocklist_t *blocklist, const char *filename, const char *charset)
{
    int prevcount;

    prevcount = blocklist->count;
    if (loadlist_p2b(blocklist, filename) == 0) {
        do_log(LOG_DEBUG, "PeerGuardian Binary: %d entries loaded", blocklist->count - prevcount);
        return 0;
    }
    blocklist_clear(blocklist, prevcount);

    prevcount = blocklist->count;
    if (loadlist_dat(blocklist, filename, charset ? charset : "ISO8859-1") == 0) {
        do_log(LOG_DEBUG, "IPFilter: %d entries loaded", blocklist->count - prevcount);
        return 0;
    }
    blocklist_clear(blocklist, prevcount);

    prevcount = blocklist->count;
    if (loadlist_p2p(blocklist, filename, charset ? charset : "ISO8859-1") == 0) {
        do_log(LOG_DEBUG, "PeerGuardian Ascii: %d entries loaded", blocklist->count - prevcount);
        return 0;
    }
    blocklist_clear(blocklist, prevcount);

    return -1;
}
