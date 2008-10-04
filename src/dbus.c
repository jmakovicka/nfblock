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
#include "blocklist.h"
#include "nfblockd.h"

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

size_t
block_sub_array_len(block_sub_entry_t **a)
{
    size_t s = 0;

    if (a == NULL)
	return 0;

    while (*a++)
	s++;

    return s;
}

dbus_bool_t
nfbd_dbus_iter_append_block_entry_v4(DBusMessageIter *dbiterp, uint32_t addr, block_sub_entry_t **ranges, uint32_t hits)
{
    DBusMessageIter dbiter_array, dbiter_struct;
    dbus_bool_t dbb = TRUE;
    size_t n_ranges = block_sub_array_len(ranges);

    if (n_ranges > NFB_RANGES_MAX) {
	do_log(LOG_WARNING, "Ignoring invalid D-Bus message contents");
	return FALSE;
    }

    /* append signal arguments */
    dbb &= dbus_message_iter_append_basic(dbiterp, DBUS_TYPE_BYTE, NFBP_IPv4_BIN__BY_REF);

    dbb &= dbus_message_iter_open_container(dbiterp, DBUS_TYPE_STRUCT, NULL, &dbiter_struct);
    dbb &= dbus_message_iter_append_basic(&dbiter_struct, DBUS_TYPE_UINT32, &addr);
    dbb &= dbus_message_iter_append_basic(&dbiter_struct, DBUS_TYPE_UINT32, &hits);
    /* if there are no labels (typically when forwarding) don't insert anything */
    /* if there is one label, insert one string */
    /* if there is more than one label, insert an array of strings */
    if (n_ranges == 1) {
    	dbb &= dbus_message_iter_append_basic(&dbiter_struct, DBUS_TYPE_STRING, &ranges[0]->name);
    }
    else if (n_ranges > 1) {
    	int i = 0;

    	dbb &= dbus_message_iter_open_container(&dbiter_struct, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &dbiter_array);
        while (n_ranges--) {
            dbb &= dbus_message_iter_append_basic(&dbiter_array, DBUS_TYPE_STRING, &ranges[i++]->name);
        }
        dbb &= dbus_message_iter_close_container(&dbiter_struct, &dbiter_array);
    }
    dbb &= dbus_message_iter_close_container(dbiterp, &dbiter_struct);

    return dbb;
}

int
nfblockd_dbus_send_signal_nfq(log_func_t do_log, time_t curtime, int signal, char action, char *fmt, ...)
{
    DBusMessage *dbmsg = NULL;
    DBusMessageIter dbiter, dbiter_sub;
    dbus_bool_t f_drop, dbb = TRUE;
    va_list ap;

    uint32_t addr = 0;
    block_sub_entry_t **ranges = NULL;
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

    if (!dbmsg)
        return -1;

    dbus_message_iter_init_append(dbmsg, &dbiter);

    va_start(ap, fmt);
    while (fmt && dbb) {
	while (*fmt) {
	    switch (*fmt++) {
	    case ADDR: addr = va_arg(ap, uint32_t); break;
	    case RANGES: ranges = va_arg(ap, block_sub_entry_t **);   break;
	    case HITS: hits = va_arg(ap, uint32_t); break;
	    }
	}
	dbb &= nfbd_dbus_iter_append_block_entry_v4(&dbiter, addr, ranges, hits);

	fmt = va_arg(ap, char *);
    }
    va_end(ap);

    /* dropped or marked rejected */
    f_drop = (action == NFBP_ACTION_DROP) ? TRUE : FALSE;
    dbb &= dbus_message_iter_append_basic(&dbiter, DBUS_TYPE_BOOLEAN, &f_drop);

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

    if (!dbb)
        do_log(LOG_CRIT, "Cannot create D-Bus message (out of memory?).");

    dbus_message_unref(dbmsg);

    return dbb ? 0 : -1;
}
