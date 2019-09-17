#Generated automatically from Makefile.in by configure.
# Makefile.in generated automatically by automake 1.4 from Makefile.am

# Copyright (C) 1994, 1995-8, 1999 Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

CC = gcc
LIB_VERS = 0.9.9.8

CFLAGS = -Wall -O3 -mtune=core2 -msse4 -ffast-math -mfpmath=sse

INCLUDE = 

all: rinecrypt

	      
aes-amd64.o: aes-amd64.S

	$(CC) $(CFLAGS) -fPIC $(INCLUDE) -c aes-amd64.S

sha512-amd64.o: sha512-amd64.S

		$(CC) $(CFLAGS) -fPIC $(INCLUDE) -c sha512-amd64.S
	
dencrypt.o: dencrypt.c

	$(CC) $(CFLAGS) -fPIC $(INCLUDE) -c dencrypt.c   

derkey_sha512.o: derkey_sha512.c

	$(CC) $(CFLAGS) -fPIC $(INCLUDE) -c derkey_sha512.c  

librinecrypt.o: librinecrypt.c

	$(CC) $(CFLAGS) -fPIC $(INCLUDE) -c librinecrypt.c  

memory.o: memory.c

	$(CC) $(CFLAGS) -fPIC $(INCLUDE) -c memory.c   

secmem.o: secmem.c

	$(CC) $(CFLAGS) -fPIC $(INCLUDE) -c secmem.c     

sha512.o: sha512.c

	$(CC) $(CFLAGS) -fPIC $(INCLUDE) -c sha512.c

random.o: random.c

	$(CC) $(CFLAGS) -fPIC $(INCLUDE) -c random.c

rinecrypt.o: rinecrypt.c 
	$(CC) $(CFLAGS)  $(INCLUDE) -c rinecrypt.c


rinecrypt:   aes-amd64.o  sha512-amd64.o dencrypt.o  derkey_sha512.o rinecrypt.o  \
              librinecrypt.o  memory.o  random.o  secmem.o  sha512.o 

	      $(CC) aes-amd64.o  sha512-amd64.o dencrypt.o  derkey_sha512.o rinecrypt.o  \
              librinecrypt.o  memory.o  random.o  secmem.o  sha512.o -o rinecrypt


clean :
	-rm -f *.o *.o core *.core rinecrypt
	-rm -f *.lo *.lo librinecrypt.so.$(LIB_VERS)
	-rm -f  *.0
	-rm -rf .libs _libs

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
