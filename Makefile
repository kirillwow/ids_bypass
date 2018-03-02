CC		= gcc
CFLAGS		= -c -Wall -D_GNU_SOURCE -g
LDFLAGS		= -lpcap
SOURCES		= server.c
INCLUDES	= -I.
OBJECTS		= $(SOURCES:.c=.o)
TARGET		= server

all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS) 
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

clean:
	rm -rf $(OBJECTS) $(TARGET)
