CFLAGS = $$(pkg-config --cflags xorg-server) -fPIC

all: altsec.so

altsec.so: altsec.o
	cc -o altsec.so -shared altsec.o $(CFLAGS)

altsec.o: altsec.c
	cc -c altsec.c altsec.h $(CFLAGS)
