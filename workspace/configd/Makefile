CC = gcc
CFLAGS = -Wall -O2 -D_GNU_SOURCE -fstack-protector-strong
LIBS = -lmicrohttpd -lcjson -ldl -lpthread
TARGET = configd
SRC = configd.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)

install:
	mkdir -p /var/json /var/log/work_log
	chmod 755 /var/json
	cp $(TARGET) /usr/local/bin/
	@echo "安装完成"

.PHONY: all clean install