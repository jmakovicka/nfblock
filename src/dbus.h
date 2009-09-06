/*

   D-Bus messaging interface

   (c) 2008 João Valverde (jpv950@gmail.com)

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


#ifndef NFBLOCKD_DBUS_H
#define NFBLOCKD_DBUS_H

#include <stdbool.h>
#include <inttypes.h>
#include <time.h>
#include <dbus/dbus.h>

#include "blocklist.h"
#include "nfblockd.h"

#define NFB_DBUS_PUBLIC_NAME "org.netfilter.nfblock"

typedef enum {
    LOG_NF_IN,
    LOG_NF_OUT,
/*    LOG_NF_FWD,*/
} dbus_log_message_t;

typedef int (*nfblock_dbus_init_t)(log_func_t do_log);

typedef int (*nfblock_dbus_send_blocked_t)(log_func_t do_log, time_t curtime,
                                           dbus_log_message_t signal,
                                           bool dropped, char *addr,
                                           block_sub_entry_t **ranges,
                                           uint32_t hits);

#endif
