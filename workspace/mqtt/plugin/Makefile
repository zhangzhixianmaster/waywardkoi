CC = gcc
CFLAGS = -Wall -O2 -fPIC -D_GNU_SOURCE
INCLUDES = -I../common -I/usr/include -I/usr/local/include

# Daemon 直接编译 common 源文件，无需链接 libmqtt_common.so
DAEMON_LIBS = -lcjson -lpaho-mqtt3as -lpaho-mqtt3a -lpaho-mqtt3c -lprotobuf-c -lssl -lcrypto -lpthread -lm

# Plugin (command relay only, no MQTT)
PLUGIN_LIBS = -lmicrohttpd -lcrypto -lssl -lcjson -lpthread -lm

DAEMON_SRC = ../client/client.c ../common/mqtt_lib.c ../common/client_auth.c ../common/mqtt_cmd.c ../common/sensor.pb-c.c
DAEMON_OUT = mqtt_daemon

PLUGIN_SRC = mqtt_plugin.c
PLUGIN_OUT = libmqtt_config.so

.PHONY: all clean install

all: $(DAEMON_OUT) $(PLUGIN_OUT)

$(DAEMON_OUT): $(DAEMON_SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(DAEMON_LIBS)

$(PLUGIN_OUT): $(PLUGIN_SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -shared -o $@ $^ $(PLUGIN_LIBS)

clean:
	rm -f $(PLUGIN_OUT) $(DAEMON_OUT) *.o

install:
	mkdir -p /lib/work_lib
	cp $(PLUGIN_OUT) /lib/work_lib/
	mkdir -p /var/json/
	cp ../file/mqtt.json /var/json/
	cp $(DAEMON_OUT) /usr/local/bin/
	@echo "MQTT 插件已安装到 /lib/work_lib/"
	@echo "MQTT daemon 已安装到 /usr/local/bin/"

.PHONY: all clean install
