CC      = gcc
CFLAGS  = -Wall -O2 -fPIC
LIBS    = -lssl -lcrypto -lcjson
TARGET  = libcert.so
SRC     = cert.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC) cert.h
	$(CC) -shared -o $(TARGET) $(SRC) $(CFLAGS) $(LIBS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	mkdir -p /usr/local/lib
	cp $(TARGET) /usr/local/lib/
	@echo "libcert.so installed to /usr/local/lib/"
