CC = gcc

CFLAGS = -Wall -Wextra -O2 -g -I/usr/local/include

LIBS = -lmqtt_common -lcjson -lpaho-mqtt3c -lpaho-mqtt3a -lpaho-mqtt3as -lprotobuf-c -lssl -lcrypto -lpthread -lm

LDFLAGS = -L../common -L/usr/local/lib

TARGET = mqtt_client

SRCS = client.c

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -g -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
