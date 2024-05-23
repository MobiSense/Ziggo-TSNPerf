# Makefile for tsnperf

CC=gcc
# CFLAGS=-Wall -O2
CFLAGS=-g -O2 -Wl,-z,noexecstack,-z,relro,-z,now -pie
LDFLAGS=-lpcap -lelf -lbpf -lconfig
TARGET=tsnperf validation

all: $(TARGET)

validation: src/validation.c pcapReader.o util.o
	$(CC) $(CFLAGS) -o validation src/validation.c pcapReader.o util.o $(LDFLAGS)

tsnperf: src/main.c pcapReader.o pcapSender.o util.o
	$(CC) $(CFLAGS) -o tsnperf src/main.c pcapReader.o pcapSender.o util.o $(LDFLAGS)

pcapReader.o: src/pcapReader.c
	$(CC) $(CFLAGS) -c src/pcapReader.c

pcapSender.o: src/pcapSender.c
	$(CC) $(CFLAGS) -c src/pcapSender.c

util.o: src/util.c
	$(CC) $(CFLAGS) -c src/util.c

clean:
	rm -f *.o $(TARGET)
