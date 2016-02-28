OBJS = bpf.o rawsock.o lib.o pktbuf.o

LIB = libpkt.a

SRCS = $(OBJS:.o=.c)

CC ?= gcc
AR ?= ar

CFLAGS = -O -Wall -g

.SUFFIXES:
.SUFFIXES: .o .c

all :		$(LIB)

.c.o :
		$(CC) $(CFLAGS) -c $<

$(LIB) :	$(OBJS)
		$(AR) ruc $(LIB) $(OBJS)

clean :
		rm -f $(OBJS) $(LIB)
