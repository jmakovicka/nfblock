#! /bin/sh -e
### BEGIN INIT INFO
# Provides:          nfblock
# Required-Start:    $network $syslog
# Required-Stop:     $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: NFblock Netfiler blocking daemon
# Description:       A PeerGardian-like daemon handling IP blocklists.
### END INIT INFO

DESC="netfilter blocking daemon"
DAEMON=/usr/sbin/nfblockd
BLOCKLIST_DIR=/var/lib/nfblock
PIDFILE=/var/run/nfblockd.pid
ENABLED=0

test -f /usr/sbin/nfblockd || exit 0
test -f /etc/default/nfblock && . /etc/default/nfblock

BLOCKLIST_FILE="$BLOCKLIST_DIR/*"

if [ "$ENABLED" = "0" ]; then
    echo "$DESC: disabled, see /etc/default/nfblock"
    exit 0
fi

case "$1" in
    start)
        echo -n "Starting $DESC:"
        echo -n " nfblockd"
        NFBLOCKD_ARGS="-d $BLOCKLIST_FILE -p $PIDFILE"
        if [ "$DBUS" = "0" ]; then
            NFBLOCKD_ARGS="$NFBLOCKD_ARGS --no-dbus"
        fi
        if [ "$SYSLOG" = "0" ]; then
            NFBLOCKD_ARGS="$NFBLOCKD_ARGS --no-syslog"
        fi
        start-stop-daemon --start --quiet --oknodo --pidfile $PIDFILE --exec $DAEMON -- $NFBLOCKD_ARGS \
            < /dev/null
        echo "."
        ;;
    stop)
        echo -n "Stopping $DESC:"
        echo -n " nfblockd"
        start-stop-daemon --stop --quiet --oknodo --pidfile $PIDFILE --exec $DAEMON
        echo "."
        ;;
    reload|force-reload)
        echo -n "Reloading $DESC:"
        echo -n " nfblockd"
        start-stop-daemon --stop --quiet --pidfile $PIDFILE --signal HUP --exec $DAEMON
        echo "."
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    *)
        echo "Usage: /etc/init.d/nfblock {start|stop|reload|restart|force-reload}"
        exit 1
esac

exit 0
