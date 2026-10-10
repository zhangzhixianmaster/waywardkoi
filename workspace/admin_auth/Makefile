CC = gcc
CFLAGS = -Wall -O2 -fPIC -fstack-protector-strong
LIBS = -lcjson -lcrypto
LDFLAGS = -lmicrohttpd -lcjson -lcrypto

LOGIN_SRC = auth.c
LOGIN_HDRS = ../libs/sms/sms.h ../libs/email/email.h ../libs/totp/totp.h ../libs/cert/cert.h
LOGIN_OUT = login

PLUGIN_SRC = admin_plugin.c
PLUGIN_OUT = libadmin.so

.PHONY: all login plugin clean install

all: login plugin

login: $(LOGIN_SRC) $(LOGIN_HDRS)
	$(CC) -o $(LOGIN_OUT) $(LOGIN_SRC) -I../cjson $(LDFLAGS) -L/usr/local/lib -lsms -lemail -ltotp -lcert -lcurl -lpthread

plugin: $(PLUGIN_SRC)
	$(CC) -shared -o $(PLUGIN_OUT) $(PLUGIN_SRC) $(CFLAGS) $(LIBS)

clean:
	rm -f $(LOGIN_OUT) $(PLUGIN_OUT)

install: plugin
	mkdir -p /lib/work_lib /var/json /data /etc
	chmod 750 /data
	cp $(PLUGIN_OUT) /lib/work_lib/
	cp admin_routes.json /var/json/admin.json
	# 安装统一配置文件
	cp file/auth_config.json /etc/auth_config.json
	# 安装登录服务
	cp $(LOGIN_OUT) /usr/local/bin/login
	@echo "============================================"
	@echo "  安装完成"
	@echo "  插件:     /lib/work_lib/libadmin.so"
	@echo "  路由:     /var/json/admin.json"
	@echo "  配置:     /etc/auth_config.json  (唯一配置文件)"
	@echo "  管理员数据: /data/admins.json"
	@echo "  服务:     /usr/local/bin/login"
	@echo "============================================"

.PHONY: all login plugin clean install