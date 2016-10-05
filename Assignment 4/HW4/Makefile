# Makefile

SHELL=/bin/bash
CC=gcc
SRCS=dnsinject.c
OBJS=dnsinject.o
CFLAGS=-std=c99 -pedantic -Wall -ggdb -D_GNU_SOURCE
LFLAGS=-lpcap
PROGRAM=dnsinject

.PHONY: depend clean

$(PROGRAM): $(SRCS) $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(PROGRAM) $(LFLAGS)

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-rm -f $(OBJS) $(PROGRAM) *.out

# DO NOT DELETE

dnsinject.o: dnsinject.c
