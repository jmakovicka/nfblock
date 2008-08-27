PKGNAME = nfblockd
VERSION = 0.6

#PROFILE = yes

DBUS=yes

ifeq ($(INSTALLROOT),)
INSTALLROOT = /usr/local
endif
ifeq ($(DBUSROOT),)
DBUSROOT = /
endif

OPTFLAGS=-Os
CFLAGS=-Wall $(OPTFLAGS) -ffast-math -DVERSION=\"$(VERSION)\" -DROOT=\"$(INSTALLROOT)\"
LDFLAGS=-lnetfilter_queue -lnfnetlink -lz
CC=gcc

ifeq ($(DBUS),yes)
CFLAGS+=-DHAVE_DBUS `pkg-config dbus-1 --cflags`
LDFLAGS+=-ldl
endif

ifneq ($(PROFILE),)
CFLAGS+=-pg
LDFLAGS+=-pg
else
CFLAGS+=-fomit-frame-pointer
LDFLAGS+=-s
endif

DISTDIR = $(PKGNAME)-$(VERSION)

DISTFILES = \
	Makefile nfblockd.c nfblockd.h dbus.c dbus.h \
	dbus-nfblockd.conf ChangeLog README \
	debian/changelog debian/control debian/copyright \
	debian/cron.daily debian/default debian/init.d \
	debian/postinst debian/postrm debian/rules \

ifeq ($(DBUS),yes)
all: nfblockd dbus.so
else
all: nfblockd
endif

.c.o:
	$(CC) $(CFLAGS) -c $<

nfblockd: nfblockd.o
	gcc -o nfblockd $(LDFLAGS) $^

dbus.so: dbus.o
	$(CC) -shared -Wl `pkg-config dbus-1 --libs` -o dbus.so dbus.o
clean:
	rm -f *.o *~ nfblockd

install:
	install -D -m 755 nfblockd $(INSTALLROOT)/sbin/nfblockd
	install -D -m 644 dbus-nfblockd.conf $(DBUSROOT)/etc/dbus-1/system.d/nfblockd.conf
	install -D -m 644 dbus.so $(INSTALLROOT)/lib/nfblockd/dbus.so

dist:
	rm -rf $(DISTDIR)
	mkdir $(DISTDIR) $(DISTDIR)/debian
	for I in $(DISTFILES) ; do cp "$$I" $(DISTDIR)/$$I ; done
	tar zcf $(PKGNAME)-$(VERSION).tgz $(PKGNAME)-$(VERSION)
	rm -rf $(DISTDIR)

.PHONY: clean
