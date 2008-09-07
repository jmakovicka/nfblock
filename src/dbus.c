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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <inttypes.h>

#include <dbus/dbus.h>

#include "dbus.h"

#define DBUS_PUBLIC_NAME "org.netfilter.nfblockd"

static unsigned char __nfbp_ipv4_bin = NFBP_IPv4_BIN;

#define NFBP_IPv4_BIN__BY_REF (&__nfbp_ipv4_bin)

static DBusConnection *dbconn = NULL;

int
nfblockd_dbus_init(log_func_t do_log)
{
    DBusError dberr;
    int req;

    dbus_error_init (&dberr);
    dbconn = dbus_bus_get (DBUS_BUS_SYSTEM, &dberr);
    if (dbus_error_is_set (&dberr)) {
        do_log(LOG_ERR, "Error connecting to dbus-daemon: %s", dberr.message);
        return -1;
    }
    do_log(LOG_INFO, "Connected to system bus.");

    /* need d-bus policy privileges for this to work */
    dbus_error_init (&dberr);
    req = dbus_bus_request_name (dbconn, DBUS_PUBLIC_NAME, DBUS_NAME_FLAG_DO_NOT_QUEUE, &dberr);
    if (dbus_error_is_set (&dberr)) {
        do_log(LOG_ERR, "Error requesting name: %s.", dberr.message);
        return -1;
    }
    if (req == DBUS_REQUEST_NAME_REPLY_EXISTS) {
        /* FIXME: replace the current name owner instead of giving up?
         * Need to request name with DBUS_NAME_FLAG_ALLOW_REPLACEMENT in that case... */
        do_log(LOG_WARNING, "nfblockd is already running. Exiting.");
        return -1;
    }

    return 0;
}



dbus_bool_t
nfbd_dbus_iter_append_block_entry(DBusMessageIter *dbiterp, uint32_t addr, char *name, uint32_t hits)
{
    DBusMessageIter dbiter_array;
    unsigned char n_label;
    dbus_bool_t dbb = TRUE;

    /* append signal arguments */
    dbb &= dbus_message_iter_append_basic(dbiterp, DBUS_TYPE_BYTE, NFBP_IPv4_BIN__BY_REF);
    dbb &= dbus_message_iter_append_basic(dbiterp, DBUS_TYPE_UINT32, &addr);
    n_label = (*name != '\0') ? 1 : 0;
    dbb &= dbus_message_iter_append_basic(dbiterp, DBUS_TYPE_BYTE, &n_label);
    /* if there are no labels (typically when forwarding) don't insert the array */
    if (n_label) {
        dbb &= dbus_message_iter_open_container(dbiterp, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &dbiter_array);
        while (n_label--) {
            dbb &= dbus_message_iter_append_basic(&dbiter_array, DBUS_TYPE_STRING, &name);
        }
        dbb &= dbus_message_iter_close_container(dbiterp, &dbiter_array);
    }
    dbb &= dbus_message_iter_append_basic(dbiterp, DBUS_TYPE_UINT32, &hits);

    return dbb;
}

int
nfblockd_dbus_send_signal_nfq(log_func_t do_log, time_t curtime, int signal, char action, char *fmt, ...)
{
    DBusMessage *dbmsg = NULL;
    DBusMessageIter     dbiter, dbiter_sub;
    dbus_bool_t dbb = TRUE;
    va_list ap;

    uint32_t addr = 0;
    char *name = "";
    uint32_t hits = 0;

    /* create dbus signal */
    switch (signal) {
    case LOG_NF_IN:
        dbmsg = dbus_message_new_signal ("/org/netfilter/nfblockd",
                                         "org.netfilter.nfblockd",
                                         "blocked_in");
        break;
    case LOG_NF_OUT:
        dbmsg = dbus_message_new_signal ("/org/netfilter/nfblockd",
                                         "org.netfilter.nfblockd",
                                         "blocked_out");
        break;
    case LOG_NF_FWD:
        dbmsg = dbus_message_new_signal ("/org/netfilter/nfblockd",
                                         "org.netfilter.nfblockd",
                                         "blocked_fwd");
        break;
    }
    if (!dbmsg) {
        dbb = FALSE;
    } else {
        dbus_message_iter_init_append(dbmsg, &dbiter);
        dbb &= dbus_message_iter_append_basic(&dbiter, DBUS_TYPE_BYTE, &action);

        va_start(ap, fmt);
        while (fmt) {
            while (*fmt) {
                switch (*fmt++) {
                case ADDR: addr = va_arg(ap, uint32_t); break;
                case NAME: name = va_arg(ap, char *);   break;
                case HITS: hits = va_arg(ap, uint32_t); break;
                }
            }
            dbb &= dbus_message_iter_open_container(&dbiter, DBUS_TYPE_STRUCT, NULL, &dbiter_sub);
            dbb &= nfbd_dbus_iter_append_block_entry(&dbiter_sub, addr, name, hits);
            dbb &= dbus_message_iter_close_container(&dbiter, &dbiter_sub);
            fmt = va_arg(ap, char *);
        }
        va_end(ap);

        /* NOTE: POSIX specifies time_t type as arithmetic type (so it can be floating point) */
        /* it would be more portable to use a string representation for time (eg: ISO 8601 with UTC),
         * but most (all?) Unix-like systems use an integral value for time_t */
        /* it's nice to have the same time stamp on all records but anyway it's optional and clients should supply their own if it's missing */
        dbb &= dbus_message_iter_open_container(&dbiter, DBUS_TYPE_VARIANT, DBUS_TYPE_INT64_AS_STRING, &dbiter_sub);
        dbb &= dbus_message_iter_append_basic(&dbiter_sub, DBUS_TYPE_INT64, &curtime);
        dbb &= dbus_message_iter_close_container(&dbiter, &dbiter_sub);

        if (dbb && dbus_connection_get_is_connected(dbconn)) {
            dbus_connection_send (dbconn, dbmsg, NULL);
        }
    }

    if (!dbb)
        do_log(LOG_CRIT, "Cannot create D-Bus message (out of memory?).");

    dbus_message_unref(dbmsg);

    return dbb ? 0 : -1;
}
