/*

   D-Bus messaging interface

   (c) 2008 João Valverde

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

#ifndef DBUS_H
#define DBUS_H

#ifdef HAVE_DBUS

int nfblockd_dbus_init();

int nfblockd_dbus_send_signal_nfq(int sigtype, int first_arg_type, ...);

int nfblockd_dbus_done();

#else

static int nfblockd_dbus_init() { }

static int nfblockd_dbus_send_signal_nfq(int sigtype, int first_arg_type, ...) { }

static int nfblockd_dbus_done()
{
}

#endif

#define DBUS_TYPE_BYTE          ((int) 'y')
#define DBUS_TYPE_UINT32        ((int) 'u')
#define DBUS_TYPE_STRING        ((int) 's')
#define DBUS_TYPE_INVALID       ((int) '\0')

typedef enum {
    LOG_NF_IN,
    LOG_NF_OUT,
    LOG_NF_FWD,
} dbus_log_message_t;

#endif
