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

/* nfblockd dbus protocol */
#define NFBP_ACTION_MARK 'm'
#define NFBP_ACTION_DROP 'd'
#define NFBP_IPv4_BIN 0x0

#define FMT_ADDR_RANGES_HITS "arh"
#define ADDR 'a'
#define RANGES 'r'
#define HITS 'h'

#define NFB_RANGES_MAX 255

typedef enum {
    LOG_NF_IN,
    LOG_NF_OUT,
    LOG_NF_FWD,
} dbus_log_message_t;

typedef void (*log_func_t) (int priority, const char *format, ...);

#endif
