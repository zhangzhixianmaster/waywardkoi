CC = gcc
CFLAGS = -Wall -O2 -fPIC
LIBS = -lcjson

TARGET = libcert_manager.so
SRC = cert_plugin.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) -shared -o $(TARGET) $(SRC) $(CFLAGS) $(LIBS)

clean:
	rm -f $(TARGET)

install:
	mkdir -p /lib/work_lib /var/json /data/certs/ca /data/certs/certs
	cp $(TARGET) /lib/work_lib/
	cp cert_routes.json /var/json/cert.json
	@echo "============================================"
	@echo "  证书管理模块已安装"
	@echo "  插件:  /lib/work_lib/libcert_manager.so"
	@echo "  路由:  /var/json/cert.json"
	@echo "  存储:  /data/certs/"
	@echo "============================================"

.PHONY: all clean install
