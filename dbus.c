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

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <inttypes.h>

#include "dbus.h"
#include "nfblockd.h"

/**************** D-Bus API *****************/

typedef struct DBusMessage DBusMessage;
typedef struct DBusConnection DBusConnection;
typedef struct DBusError DBusError;

typedef uint32_t dbus_bool_t;

struct DBusError
{
    const char *name;    /**< public error name field */
    const char *message; /**< public error message field */

    unsigned int dummy1 : 1; /**< placeholder */
    unsigned int dummy2 : 1; /**< placeholder */
    unsigned int dummy3 : 1; /**< placeholder */
    unsigned int dummy4 : 1; /**< placeholder */
    unsigned int dummy5 : 1; /**< placeholder */

    void *padding1; /**< placeholder */
};

typedef enum {
    DBUS_BUS_SESSION,    /**< The login session bus */
    DBUS_BUS_SYSTEM,     /**< The systemwide bus */
    DBUS_BUS_STARTER     /**< The bus that started us, if any */
} DBusBusType;

#define DBUS_REQUEST_NAME_REPLY_EXISTS         3 /**< Service is already in the queue */

#define DBUS_NAME_FLAG_DO_NOT_QUEUE      0x4 /**< If we can not become the primary owner do not place us in the queue */

static void (*dbus_error_init) (DBusError *error);
static DBusConnection * (*dbus_bus_get) (DBusBusType type, DBusError *error);
static dbus_bool_t (*dbus_error_is_set) (const DBusError *error);
static int (*dbus_bus_request_name) (DBusConnection *connection, const char *name,
                                     unsigned int flags, DBusError *error);
static DBusMessage* (*dbus_message_new_signal) (const char  *path, const char  *interface,
                                                const char  *name);
static dbus_bool_t (*dbus_message_append_args_valist) (DBusMessage *message, int first_arg_type,
                                                       va_list var_args);
static void (*dbus_message_unref) (DBusMessage *message);
static dbus_bool_t (*dbus_connection_get_is_connected) (DBusConnection *connection);
static dbus_bool_t (*dbus_connection_send) (DBusConnection *connection, DBusMessage *message,
                                            uint32_t *client_serial);

/********************************************/

#define DBUS_PUBLIC_NAME "org.netfilter.nfblockd"

static DBusConnection *dbconn = NULL;

static void *dbus_lh = NULL;

#define do_dlsym(symbol)                                                \
    do {                                                                \
        symbol = dlsym(dbus_lh, # symbol);                              \
        err = dlerror();                                                \
        if (err) {                                                      \
            nfblockd_do_log(LOG_ERR, "Cannot get symbol %s: %s", # symbol, err); \
            goto out_err;                                               \
        }                                                               \
    } while (0)

static int
open_dbus()
{
    char *err;
    
    dbus_lh = dlopen("libdbus-1.so", RTLD_NOW);
    if (!dbus_lh) {
        nfblockd_do_log(LOG_ERR, "dlopen() failed");
        return -1;
    }
    dlerror(); // clear the error flag
    
    do_dlsym(dbus_error_init);
    do_dlsym(dbus_bus_get);
    do_dlsym(dbus_error_is_set);
    do_dlsym(dbus_bus_request_name);
    do_dlsym(dbus_message_new_signal);
    do_dlsym(dbus_message_append_args_valist);
    do_dlsym(dbus_message_unref);
    do_dlsym(dbus_connection_get_is_connected);
    do_dlsym(dbus_connection_send);

    return 0;
    
out_err:
    dlclose(dbus_lh);
    return -1;
}

int
nfblockd_dbus_init()
{
    DBusError dberr;
    int req;
    
    if (open_dbus() < 0) {
        nfblockd_do_log(LOG_ERR, "Cannot load D-Bus library");
        return -1;
    }
        
    dbus_error_init (&dberr);
    dbconn = dbus_bus_get (DBUS_BUS_SYSTEM, &dberr); 
    if (dbus_error_is_set (&dberr)) {
        nfblockd_do_log(LOG_ERR, "Error connecting to dbus-daemon: %s", dberr.message);
        return -1;
    }
    nfblockd_do_log(LOG_INFO, "Connected to system bus.");
        
    /* need d-bus policy priviledges for this to work */
    dbus_error_init (&dberr);
    req = dbus_bus_request_name (dbconn, DBUS_PUBLIC_NAME, DBUS_NAME_FLAG_DO_NOT_QUEUE, &dberr);
    if (dbus_error_is_set (&dberr)) {
        nfblockd_do_log(LOG_ERR, "Error requesting name: %s.", dberr.message);
        return -1;
                
    }
    if (req == DBUS_REQUEST_NAME_REPLY_EXISTS) {
        /* FIXME: replace the current name owner instead of giving up?
         * Need to request name with DBUS_NAME_FLAG_ALLOW_REPLACEMENT in that case... */
        nfblockd_do_log(LOG_WARNING, "nfblockd is already running. Exiting.");
        return -1;
    }

    return 0;
}

int
nfblockd_dbus_done()
{
    if (dbus_lh)
        return dlclose(dbus_lh);

    return 0;
}

int
nfblockd_dbus_send_signal_nfq(int sigtype, int first_arg_type, ...)
{
    DBusMessage *dbmsg = NULL;
    va_list ap;
    int ret = -1;

    if (!dbus_lh)
        return -1;

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
        nfblockd_do_log(LOG_CRIT, "Cannot create D-Bus message (out of memory?).");
        goto out;
    }
        
    va_start(ap, first_arg_type);
    if (!dbus_message_append_args_valist(dbmsg, first_arg_type, ap)) {
        nfblockd_do_log(LOG_CRIT, "Cannot append D-Bus message arguments (out of memory?).");
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
