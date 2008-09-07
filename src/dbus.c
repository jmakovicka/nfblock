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

#ifdef HAVE_DBUS

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <inttypes.h>

#include <dbus/dbus.h>

#include "nfblockd.h"

#define DBUS_PUBLIC_NAME "org.netfilter.nfblockd"

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

    /* need d-bus policy priviledges for this to work */
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

int
nfblockd_dbus_send_signal_nfq(log_func_t do_log, int sigtype, int first_arg_type, ...)
{
    DBusMessage *dbmsg = NULL;
    va_list ap;
    int ret = -1;

    /* create dbus signal */
    switch (sigtype) {
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
        do_log(LOG_CRIT, "Cannot create D-Bus message (out of memory?).");
        goto out;
    }

    va_start(ap, first_arg_type);
    if (!dbus_message_append_args_valist(dbmsg, first_arg_type, ap)) {
        do_log(LOG_CRIT, "Cannot append D-Bus message arguments (out of memory?).");
        goto out;
    }
    va_end(ap);

    if (dbus_connection_get_is_connected(dbconn)) {
        dbus_connection_send (dbconn, dbmsg, NULL); /* this needs flushing! */
    }

    ret = 0;

out:
    dbus_message_unref(dbmsg);
    return ret;
}

#endif
