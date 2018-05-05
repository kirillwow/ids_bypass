CC		    = gcc
CFLAGS		= -c -Wall -D_GNU_SOURCE -g
LDFLAGS		= -lpcap
SOURCES		= inject_server.c icmp_server.c rst_server.c
INCLUDES	= -I.
TARGET		= inject_server icmp_server rst_server

all: $(SOURCES) $(TARGET)

inject_server: inject_server.o
	$(CC) inject_server.o -o $@ $(LDFLAGS)
    
icmp_server: icmp_server.o
	$(CC) icmp_server.o -o $@ $(LDFLAGS)
    
rst_server: rst_server.o
	$(CC) rst_server.o -o $@ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

clean:
	rm -rf *.o $(TARGET)
