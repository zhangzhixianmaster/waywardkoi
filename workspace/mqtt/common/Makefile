CC = gcc

GFLAGS = -Wall -fPIC -I/usr/local/include -I/usr/include

SHARED = -shared

LIBS = -lcjson -lpaho-mqtt3c -lpaho-mqtt3a -lpaho-mqtt3as -lprotobuf-c -lssl -lcrypto -lpthread -lm

TARGET = libmqtt_common.so

LIB_PATH:=/usr/local/lib/

SRCS = $(wildcard *.c)

OBJS = $(SRCS:.c=.o)

.PHONY: all clean install
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(SHARED) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(GFLAGS) -g -c $< -o $@

install: $(TARGET)
	cp $(TARGET) $(LIB_PATH)
	ldconfig $(LIB_PATH)

clean:
	rm -f $(OBJS) $(TARGET)
	rm -f $(LIB_PATH)/$(TARGET)
