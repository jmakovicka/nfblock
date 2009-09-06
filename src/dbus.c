/*

  D-Bus messaging interface

  (c) 2008 João Valverde (jpv950@gmail.com)

  (c) 2008 Jindrich Makovicka (makovick@gmail.com)

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

#include <syslog.h>
#include "dbus.h"

static DBusConnection *dbconn = NULL;

int
nfblock_dbus_init(log_func_t do_log)
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
    req = dbus_bus_request_name (dbconn, NFB_DBUS_PUBLIC_NAME,
                                 DBUS_NAME_FLAG_DO_NOT_QUEUE, &dberr);
    if (dbus_error_is_set (&dberr)) {
        do_log(LOG_ERR, "Error requesting name: %s.", dberr.message);
        return -1;
    }
    if (req == DBUS_REQUEST_NAME_REPLY_EXISTS) {
        /* FIXME: replace the current name owner instead of giving up?
         * Need to request name with DBUS_NAME_FLAG_ALLOW_REPLACEMENT
         * in that case... */
        do_log(LOG_WARNING, "nfblockd is already running. Exiting.");
        return -1;
    }

    return 0;
}

dbus_bool_t
nfblock_dbus_message_append_blocked(DBusMessage *dbmsg,
                                    const char *addr,
                                    block_sub_entry_t **ranges,
                                    uint32_t hits,
                                    bool dropped,
                                    time_t curtime)
{
    DBusMessageIter dbiter;
    dbus_bool_t dbb = TRUE;
    struct tm curtime_tm;
    char tstamp[8 + 1] = "::"; /* "HH:MM:SS" */
    char *s = NULL;

    dbus_message_iter_init_append(dbmsg, &dbiter);

    /* ipv4 address */
    dbb &= dbus_message_iter_append_basic(&dbiter, DBUS_TYPE_STRING, &addr);
    /* label */
    dbb &= dbus_message_iter_append_basic(&dbiter, DBUS_TYPE_STRING,
                                          &(ranges[0]->name));
    /* timestamp */
    strftime(tstamp, sizeof(tstamp), "%T", localtime_r(&curtime, &curtime_tm));
    s = &tstamp[0];
    dbb &= dbus_message_iter_append_basic(&dbiter, DBUS_TYPE_STRING, &s);
    /* hits */
    dbb &= dbus_message_iter_append_basic(&dbiter, DBUS_TYPE_UINT32, &hits);
    /* dropped */
    dbb &= dbus_message_iter_append_basic(&dbiter, DBUS_TYPE_BOOLEAN, &dropped);

    return dbb;
}

int
nfblock_dbus_send_blocked(log_func_t do_log, time_t curtime,
                          dbus_log_message_t signal, bool dropped,
                          char *addr, block_sub_entry_t **ranges,
                          uint32_t hits)
{
    DBusMessage *dbmsg = NULL;
    dbus_bool_t dbb = TRUE;

    /* create dbus signal */
    switch (signal) {
    case LOG_NF_IN:
        dbmsg = dbus_message_new_signal ("/org/netfilter/nfblock",
                                         "org.netfilter.nfblock.Blocked",
                                         "blocked_in");
        break;
    case LOG_NF_OUT:
        dbmsg = dbus_message_new_signal ("/org/netfilter/nfblock",
                                         "org.netfilter.nfblock.Blocked",
                                         "blocked_out");
        break;
        /*
                 case LOG_NF_FWD:
                 dbmsg = dbus_message_new_signal ("/org/netfilter/nfblock",
                 "org.netfilter.nfblock.Blocked",
                 "blocked_fwd");
                 assert(0);
                 break;
        */
    }

    if (!dbmsg)
        return -1;

    dbb &= nfblock_dbus_message_append_blocked(dbmsg, addr, ranges,
                                               hits, dropped, curtime);

    if (dbb && dbus_connection_get_is_connected(dbconn)) {
        dbus_connection_send (dbconn, dbmsg, NULL);
    }

    if (!dbb)
        do_log(LOG_CRIT, "Cannot create D-Bus message (out of memory?).");

    dbus_message_unref(dbmsg);

    return dbb ? 0 : -1;
}
