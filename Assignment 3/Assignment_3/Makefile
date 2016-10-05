CC=gcc
CFLAGS=-g -Wall 
LIBS=-lpthread -lcrypto
pbproxy: pbproxy.o server.o client.o aes_init.o 
	$(CC) -o pbproxy pbproxy.o server.o client.o aes_init.o $(CFLAGS) $(LIBS)
.PHONY: clean
clean:
	rm -f *.o pbproxy *.log