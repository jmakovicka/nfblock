PKGNAME = nfblockd
VERSION = 0.6

#PROFILE ?= yes

#DEBUG ?= yes

DBUS ?= yes
ZLIB ?= yes
#LOWMEM ?= yes

prefix ?= /usr/local
SBINDIR ?= $(prefix)/sbin
DBUSCONFDIR ?= $(prefix)/etc/dbus-1/system.d
PLUGINDIR ?= $(prefix)/lib/nfblockd

OBJS=src/nfblockd.o src/stream.o src/blocklist.o src/parser.o
OPTFLAGS=-Os
CFLAGS=-Wall $(OPTFLAGS) -ffast-math -DVERSION=\"$(VERSION)\" -DPLUGINDIR=\"$(PLUGINDIR)\"
LDFLAGS=-lnetfilter_queue -lnfnetlink -lz
CC=gcc

ifeq ($(LOWMEM),yes)
DBUS=no
CFLAGS+=-DLOWMEM
endif

ifeq ($(ZLIB),yes)
CFLAGS+=-DHAVE_ZLIB
LDFLAGS+=-lz
endif

ifeq ($(DBUS),yes)
CFLAGS+=-DHAVE_DBUS `pkg-config dbus-1 --cflags` -fPIC
LDFLAGS+=-ldl
endif

ifeq ($(PROFILE),yes)
CFLAGS+=-pg
LDFLAGS+=-pg
else
ifeq ($(DEBUG),yes)
CFLAGS+=-ggdb3
LDFLAGS+=-ggdb3
else
CFLAGS+=-fomit-frame-pointer
LDFLAGS+=-s
endif
endif

DISTDIR = $(PKGNAME)-$(VERSION)

DISTFILES = \
	Makefile \
	src/nfblockd.c src/nfblockd.h \
	src/blocklist.c src/blocklist.h \
	src/parser.c src/parser.h \
	src/stream.c src/stream.h \
	src/dbus.c src/dbus.h \
	dbus-nfblockd.conf ChangeLog README \
	debian/changelog debian/control debian/copyright \
	debian/cron.daily debian/default debian/init.d \
	debian/postinst debian/postrm debian/rules \

ifeq ($(DBUS),yes)
all: src/nfblockd src/dbus.so
else
all: src/nfblockd
endif

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

src/nfblockd: $(OBJS)
	echo $(OBJS)
	gcc -o $@ $(LDFLAGS) $^

src/dbus.so: src/dbus.o
	$(CC) -shared -Wl `pkg-config dbus-1 --libs` -o $@ $^
clean:
	rm -f *~ src/*.o src/*~ src/nfblockd src/dbus.so

install:
	install -D -m 755 src/nfblockd $(SBINDIR)/nfblockd
	install -D -m 644 dbus-nfblockd.conf $(DBUSCONFDIR)/nfblockd.conf
	install -D -m 644 src/dbus.so $(PLUGINDIR)/dbus.so

dist:
	rm -rf $(DISTDIR)
	mkdir $(DISTDIR) $(DISTDIR)/debian
	for I in $(DISTFILES) ; do cp "$$I" $(DISTDIR)/$$I ; done
	tar zcf $(PKGNAME)-$(VERSION).tgz $(PKGNAME)-$(VERSION)
	rm -rf $(DISTDIR)

.PHONY: clean
