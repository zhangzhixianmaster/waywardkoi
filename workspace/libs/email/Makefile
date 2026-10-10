CC      = gcc
CFLAGS  = -Wall -O2 -fPIC
LIBS    = -lcurl -lssl -lcrypto -lcjson
TARGET  = libemail.so
SRC     = email.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC) email.h
	$(CC) -shared -o $(TARGET) $(SRC) $(CFLAGS) $(LIBS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	mkdir -p /usr/local/lib
	cp $(TARGET) /usr/local/lib/
	@echo "libemail.so installed to /usr/local/lib/"
