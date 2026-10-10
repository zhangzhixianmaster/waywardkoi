CC = gcc
CFLAGS = -Wall -O2 -fPIC
LIBS = -lssl -lcrypto -lcjson
TARGET = libtotp.so
SRC = totp.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC) totp.h
	$(CC) -shared -o $(TARGET) $(SRC) $(CFLAGS) $(LIBS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	mkdir -p /usr/local/lib
	cp $(TARGET) /usr/local/lib/
	@echo "libtotp.so installed to /usr/local/lib/"
