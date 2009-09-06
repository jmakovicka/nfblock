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

#ifndef NFBLOCKD_H
#define NFBLOCKD_H

#include <stdlib.h>
#include <inttypes.h>

#define IP_STRING_SIZE 16

void do_log(int priority, const char *format, ...);
typedef void (*log_func_t) (int priority, const char *format, ...);

void ip2str(char *dst, uint32_t ip);

#define CHECK_OOM(ptr)                                                  \
    do {                                                                \
        if (!ptr) {                                                     \
            do_log(LOG_CRIT, "Out of memory in %s (%s:%d)",             \
                   __func__, __FILE__, __LINE__);                       \
            exit (-1);                                                  \
        }                                                               \
    } while(0);                                                         \

#endif
