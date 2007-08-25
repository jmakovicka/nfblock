PKGNAME = nfblockd
VERSION = 0.1

ifeq ($(INSTALLROOT),)
INSTALLROOT = /usr/local
endif
OPTFLAGS=-O3
#OPTFLAGS=-O3 -march=pentium-m -mtune=pentium-m
#OPTFLAGS=-ggdb3 -O0
CFLAGS=-Wall $(OPTFLAGS) -fomit-frame-pointer -ffast-math -DVERSION=\"$(VERSION)\"
LDFLAGS=-lnetfilter_queue -lnfnetlink -lz -s
CC=gcc

DISTDIR = $(PKGNAME)-$(VERSION)

DISTFILES = \
	Makefile nfblockd.c ChangeLog README \
	debian/changelog debian/control debian/copyright \
	debian/rules \

all: nfblockd

.c.o:
	$(CC) $(CFLAGS) -c $<

nfblockd: nfblockd.o
	gcc -o nfblockd $(LDFLAGS) $<

clean:
	rm -f *.o *~ nfblockd

install:
	install -D -m 755 nfblockd $(INSTALLROOT)/sbin/nfblockd

dist:
	rm -rf $(DISTDIR)
	mkdir $(DISTDIR) $(DISTDIR)/debian
	for I in $(DISTFILES) ; do cp "$$I" $(DISTDIR)/$$I ; done
	tar zcf $(PKGNAME)-$(VERSION).tgz $(PKGNAME)-$(VERSION)
	rm -rf $(DISTDIR)

.PHONY: clean
