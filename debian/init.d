#! /bin/sh
#
#

DESC="netfilter blocking daemon"
DAEMON=/usr/sbin/nfblockd
BLOCKLIST_DIR=/var/lib/nfblockd
PIDFILE=/var/run/nfblockd.pid
ENABLED=0

test -f /usr/sbin/nfblockd || exit 0
test -f /etc/default/nfblockd && . /etc/default/nfblockd

BLOCKLIST_FILE=$BLOCKLIST_DIR/`basename $BLOCKLIST_URL`

test -f $BLOCKLIST_FILE || exit 0

if [ "$ENABLED" = "0" ]; then
    echo "$DESC: disabled, see /etc/default/nfblockd"
    exit 0
fi

case "$1" in
    start)
	echo -n "Starting $DESC:"
	echo -n " nfblockd"
	NFBLOCKD_ARGS="-d $BLOCKLIST_FILE"
	start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON -- $NFBLOCKD_ARGS \
	    < /dev/null
	echo "."
	;;
    stop)
	echo -n "Stopping $DESC:"
	echo -n " nfblockd"
	start-stop-daemon --stop --quiet --pidfile $PIDFILE --exec $DAEMON
	echo "."
	;;
    reload|force-reload)
	echo -n "Reloading $DESC:"
	echo -n " nfblockd"
	start-stop-daemon --stop --quiet --pidfile $PIDFILE --signal HUP --exec $DAEMON
	;;
    restart)
	$0 stop
	$0 start
	;;
    *)
	echo "Usage: /etc/init.d/nfblockd {start|stop|reload|restart|force-reload}"
	exit 1
esac

exit 0
