CC = gcc
CFLAGS = -Wall -O2 -fPIC
LIBS =
TARGET = libsms.so
SRC = sms.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC) sms.h
	$(CC) -shared -o $(TARGET) $(SRC) $(CFLAGS) $(LIBS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	mkdir -p /usr/local/lib
	cp $(TARGET) /usr/local/lib/
	@echo "libsms.so installed to /usr/local/lib/"
	@echo "Run: ldconfig (optional)"
