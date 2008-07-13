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
CFLAGS=-Wall $(OPTFLAGS) -ffast-math -DVERSION=\"$(VERSION)\"
LDFLAGS=-lnetfilter_queue -lnfnetlink -lz
CC=gcc

ifeq ($(DBUS),yes)
CFLAGS+=-DHAVE_DBUS
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

all: nfblockd

.c.o:
	$(CC) $(CFLAGS) -c $<

nfblockd: nfblockd.o dbus.o
	gcc -o nfblockd $(LDFLAGS) $^

clean:
	rm -f *.o *~ nfblockd

install:
	install -D -m 755 nfblockd $(INSTALLROOT)/sbin/nfblockd
	install -D -m 644 dbus-nfblockd.conf $(DBUSROOT)/etc/dbus-1/system.d/nfblockd.conf

dist:
	rm -rf $(DISTDIR)
	mkdir $(DISTDIR) $(DISTDIR)/debian
	for I in $(DISTFILES) ; do cp "$$I" $(DISTDIR)/$$I ; done
	tar zcf $(PKGNAME)-$(VERSION).tgz $(PKGNAME)-$(VERSION)
	rm -rf $(DISTDIR)

.PHONY: clean
