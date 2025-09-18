MAJORV	= 0
MINORV	= 2
PATCHL	= 0
PREREL	= -pre

ifndef PREREL
VERSION	= $(MAJORV).$(MINORV).$(PATCHL)$(PREREL)
else
VERSION = 9999
endif

PKGCONF := $(shell pkg-config --cflags xorg-server)
XORGEXTDIR := $(shell pkg-config --variable=moduledir xorg-server)/extenstions

EXTRA_CFLAGS += $(PKGCONF)
EXTRA_CFLAGS += -fPIC -std=gnu99
EXTRA_CFLAGS += -Wall -Werror -Wpedantic
EXTRA_CFLAGS += -DVERSION=$(VERSION)
EXTRA_CFLAGS += -DMAJORV=$(MAJORV) -DMINORV=$(MINORV) -DPATCHL=$(PATCHL)

all: altsec.so

altsec.so: altsec.o
	cc -o altsec.so -shared $(CFLAGS) $(EXTRA_CFLAGS) altsec.o

altsec.o: altsec.c
	cc -c altsec.c $(CFLAGS) $(EXTRA_CFLAGS)

xext-altsec-$(VERSION).tar.gz: altsec.c Makefile README.rst 90-altsec.conf.sample
	tar -czf $@ $^

tarball: xext-altsec-$(VERSION).tar.gz

install: altsec.so
	install -pD altsec.so $(DESTDIR)/$(XORGEXTDIR)/altsec.so

clean:
	-rm altsec.o

distclean: clean
	-rm altsec.so

.PHONY: all archive clean distclean install tarball
