#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/statfs.h>
#include <sys/vfs.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include "../common/mqtt_lib.h"
#include "../common/mqtt_cmd.h"
#include "../common/sensor.pb-c.h"

#define DEV_MSG_TOPIC_HEAD  "client/dev/"

/* Safe string copy helper */
#define SAFE_STRCPY(dst, src, size) \
    do { \
        size_t _len = strlen(src); \
        if (_len >= (size)) _len = (size) - 1; \
        memcpy(dst, src, _len); \
        dst[_len] = '\0'; \
    } while (0)

char client_topic[256] = DEV_MSG_TOPIC_HEAD;

int mqtt_msgarrvd(void *context, char *topicName, int topicLen, MQTTAsync_message *message);
int sub_finished = 0;
int sub_subscribed = 0;
int sub_disc_finished = 0;

char *mqtt_usr = NULL;

/* 全局MQTT数据指针，供epoll超时回调使用 */
static Mqtt_data *g_mqtt_data = NULL;

/* Forward declaration */
static int async_send(MQTTAsync client, const char *topic, const void *payload, int payloadlen, int qos);
static int async_send_str(MQTTAsync client, const char *topic, const char *str, int qos);
static void send_device_info(Mqtt_data *data);
static void send_network_info(Mqtt_data *data);
static void send_log_info(Mqtt_data *data);
static int get_next_timeout_ms(Mqtt_data *data);

/* 客户端认证状态文件（供插件读取当前运行状态） */
#define CLIENT_AUTH_STATUS_FILE "/data/work/client_auth_status"

static void write_client_auth_status(int authorized) {
	/* 确保目录存在 */
	mkdir("/data/work", 0755);
	FILE *fp = fopen(CLIENT_AUTH_STATUS_FILE, "w");
	if (fp) {
		fprintf(fp, "%d", authorized);
		fclose(fp);
	}
}

static int read_client_auth_status(void) {
	FILE *fp = fopen(CLIENT_AUTH_STATUS_FILE, "r");
	if (!fp) return 0;
	int val = 0;
	fscanf(fp, "%d", &val);
	fclose(fp);
	return val;
}

/* ==================== 辅助: 读取文件内容 ==================== */
static int read_file(const char *path, char *buf, size_t len) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    if (!fgets(buf, (int)len, fp)) { fclose(fp); return -1; }
    fclose(fp);
    size_t l = strlen(buf);
    while (l > 0 && (buf[l-1] == '\n' || buf[l-1] == '\r')) buf[--l] = '\0';
    return 0;
}

/* ==================== 系统信息采集 ==================== */
static void get_system_info_json(char *buf, size_t len, const char *dev_uuid) {
    struct utsname sys_info = {0};
    uname(&sys_info);

    char hostname[64] = {0};
    read_file("/proc/sys/kernel/hostname", hostname, sizeof(hostname));
    if (!hostname[0]) strncpy(hostname, sys_info.nodename, sizeof(hostname)-1);

    /* 读取DMI信息 */
    char vendor[64] = {0}, product[64] = {0}, serial[64] = {0};
    read_file("/sys/class/dmi/id/sys_vendor", vendor, sizeof(vendor));
    read_file("/sys/class/dmi/id/product_name", product, sizeof(product));
    read_file("/sys/class/dmi/id/product_serial", serial, sizeof(serial));

    /* CPU型号从 /proc/cpuinfo */
    char cpu_name[128] = {0};
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "model name", 10) == 0) {
                char *p = strchr(line, ':');
                if (p) {
                    p++; while (*p == ' ' || *p == '\t') p++;
                    strncpy(cpu_name, p, sizeof(cpu_name)-1);
                    size_t l = strlen(cpu_name);
                    while (l > 0 && (cpu_name[l-1] == '\n' || cpu_name[l-1] == '\r')) cpu_name[--l] = '\0';
                }
                break;
            }
        }
        fclose(fp);
    }

    /* 内存总量 */
    long mem_total_kb = 0;
    fp = fopen("/proc/meminfo", "r");
    if (fp) {
        char line[128];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "MemTotal:", 9) == 0) {
                sscanf(line, "MemTotal: %ld", &mem_total_kb);
                break;
            }
        }
        fclose(fp);
    }

    /* 磁盘总量 (根文件系统) */
    long disk_total_mb = 0;
    struct statfs fs;
    if (statfs("/", &fs) == 0) {
        disk_total_mb = (long)((unsigned long long)fs.f_blocks * fs.f_bsize / 1024 / 1024);
    }

    /* 运行时间 */
    double uptime_sec = 0;
    fp = fopen("/proc/uptime", "r");
    if (fp) { fscanf(fp, "%lf", &uptime_sec); fclose(fp); }
    long uptime_d = (long)uptime_sec / 86400;
    long uptime_h = ((long)uptime_sec % 86400) / 3600;
    long uptime_m = ((long)uptime_sec % 3600) / 60;
    char uptime_str[64];
    snprintf(uptime_str, sizeof(uptime_str), "%ld天%ld时%ld分", uptime_d, uptime_h, uptime_m);

    snprintf(buf, len,
        "{\"type\":\"device\",\"dev_uuid\":\"%s\","
        "\"hostname\":\"%s\",\"os\":\"%s\",\"kernel\":\"%s\",\"arch\":\"%s\","
        "\"vendor\":\"%s\",\"product\":\"%s\",\"serial\":\"%s\","
        "\"cpu\":\"%s\",\"mem_total_mb\":%ld,"
        "\"disk_total_mb\":%ld,\"uptime\":\"%s\"}",
        dev_uuid,
        hostname, sys_info.sysname, sys_info.release, sys_info.machine,
        vendor, product, serial,
        cpu_name, mem_total_kb / 1024,
        disk_total_mb, uptime_str);
}

/* ==================== 硬件信息采集 (CPU/内存/磁盘使用率) ==================== */
static void get_hardware_info_json(char *buf, size_t len, const char *dev_uuid) {
    /* CPU使用率: 读两次/proc/stat取差值 */
    static long prev_idle = -1, prev_total = -1;
    int cpu_pct = 0;
    FILE *fp = fopen("/proc/stat", "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            long user, nice, system, idle, iowait, irq, softirq, steal;
            if (sscanf(line, "cpu %ld %ld %ld %ld %ld %ld %ld %ld",
                       &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal) >= 4) {
                long cur_idle = idle + iowait;
                long cur_total = user + nice + system + idle + iowait + irq + softirq + steal;
                if (prev_idle >= 0) {
                    long diff_idle = cur_idle - prev_idle;
                    long diff_total = cur_total - prev_total;
                    if (diff_total > 0) cpu_pct = (int)(100 - (diff_idle * 100 / diff_total));
                }
                prev_idle = cur_idle;
                prev_total = cur_total;
            }
        }
        fclose(fp);
    }

    /* 内存使用率 */
    long mem_total = 0, mem_avail = 0;
    int mem_pct = 0;
    fp = fopen("/proc/meminfo", "r");
    if (fp) {
        char line[128];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "MemTotal:", 9) == 0) sscanf(line, "MemTotal: %ld", &mem_total);
            if (strncmp(line, "MemAvailable:", 13) == 0) sscanf(line, "MemAvailable: %ld", &mem_avail);
        }
        fclose(fp);
    }
    if (mem_total > 0) mem_pct = (int)(100 - (mem_avail * 100 / mem_total));

    /* 磁盘使用率 */
    int disk_pct = 0;
    long disk_total_mb = 0, disk_free_mb = 0;
    struct statfs fs;
    if (statfs("/", &fs) == 0) {
        disk_total_mb = (long)((unsigned long long)fs.f_blocks * fs.f_bsize / 1024 / 1024);
        disk_free_mb = (long)((unsigned long long)fs.f_bavail * fs.f_bsize / 1024 / 1024);
        if (disk_total_mb > 0) disk_pct = (int)(100 - (disk_free_mb * 100 / disk_total_mb));
    }

    snprintf(buf, len,
        "{\"type\":\"hardware\",\"dev_uuid\":\"%s\","
        "\"cpu_pct\":%d,\"mem_pct\":%d,\"mem_total_mb\":%ld,\"mem_avail_mb\":%ld,"
        "\"disk_pct\":%d,\"disk_total_mb\":%ld,\"disk_free_mb\":%ld}",
        dev_uuid, cpu_pct, mem_pct, mem_total/1024, mem_avail/1024,
        disk_pct, disk_total_mb, disk_free_mb);
}

/* ==================== 网络信息采集 ==================== */
static void get_network_info_json(char *buf, size_t len, const char *dev_uuid) {
    char ipv4[32] = "0.0.0.0";
    char mac[32] = "00:00:00:00:00:00";
    unsigned long rx = 0, tx = 0;
    char iface[32] = "eth0";

    /* 找到第一个非lo网卡 */
    DIR *d = opendir("/sys/class/net");
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.' || strcmp(ent->d_name, "lo") == 0) continue;
            strncpy(iface, ent->d_name, sizeof(iface)-1);
            break;
        }
        closedir(d);
    }

    /* MAC地址 */
    char mac_path[128];
    snprintf(mac_path, sizeof(mac_path), "/sys/class/net/%s/address", iface);
    char mac_buf[32] = {0};
    if (read_file(mac_path, mac_buf, sizeof(mac_buf)) == 0 && mac_buf[0]) {
        strncpy(mac, mac_buf, sizeof(mac)-1);
    }

    /* RX/TX字节 */
    char stat_path[128];
    char stat_buf[64];
    snprintf(stat_path, sizeof(stat_path), "/sys/class/net/%s/statistics/rx_bytes", iface);
    if (read_file(stat_path, stat_buf, sizeof(stat_buf)) == 0) rx = strtoul(stat_buf, NULL, 10);
    snprintf(stat_path, sizeof(stat_path), "/sys/class/net/%s/statistics/tx_bytes", iface);
    if (read_file(stat_path, stat_buf, sizeof(stat_buf)) == 0) tx = strtoul(stat_buf, NULL, 10);

    /* IPv4: 使用getifaddrs获取 */
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, iface) == 0) {
                struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &sin->sin_addr, ipv4, sizeof(ipv4));
                break;
            }
        }
        freeifaddrs(ifaddr);
    }

    snprintf(buf, len,
        "{\"type\":\"network\",\"dev_uuid\":\"%s\","
        "\"iface\":\"%s\",\"ipv4\":\"%s\",\"mac\":\"%s\",\"rx_bytes\":%lu,\"tx_bytes\":%lu}",
        dev_uuid, iface, ipv4, mac, rx, tx);
}

/* ==================== 日志信息采集 ==================== */
static void get_log_info_json(char *buf, size_t len, const char *dev_uuid) {
    snprintf(buf, len,
        "{\"type\":\"log\",\"dev_uuid\":\"%s\",\"level\":\"info\",\"msgs\":[\"system running\"]}",
        dev_uuid);
}

/* ==================== Protobuf 编解码 (直接二进制,无Base64) ==================== */

/* 序列化为protobuf二进制 → 返回 malloc 的 buffer 和长度 */
static uint8_t* pb_encode_sensor_data(const char *dev_uuid, const char *type,
                                       const char *payload_json, size_t *out_len) {
    SensorData msg = SENSOR_DATA__INIT;
    msg.device_id = (char *)dev_uuid;
    msg.timestamp = (int64_t)time(NULL);
    msg.value = 0.0;
    msg.type = (char *)type;
    msg.payload_json = (char *)payload_json;

    size_t packed_size = sensor_data__get_packed_size(&msg);
    uint8_t *packed_buf = malloc(packed_size);
    if (!packed_buf) return NULL;
    sensor_data__pack(&msg, packed_buf);
    *out_len = packed_size;
    return packed_buf;
}

/* protobuf二进制 → 反序列化 → 返回 SensorData */
static SensorData* pb_decode_sensor_data(const uint8_t *data, size_t len) {
    if (!data || len == 0) return NULL;
    return sensor_data__unpack(NULL, len, data);
}

/* ==================== 各类型消息发送 (独立通道) ==================== */
static void send_device_info(Mqtt_data *data) {
    if (!data->device_cfg.enabled || !data->client_auth_received) return;

    char json_buf[2048] = {0};
    get_system_info_json(json_buf, sizeof(json_buf), data->dev_uuid);

    size_t pb_len = 0;
    uint8_t *pb = pb_encode_sensor_data(data->dev_uuid, "device", json_buf, &pb_len);
    if (!pb) return;

    log_message("[CLIENT] Sending SYSTEM info to %s (pb, len=%zu)", data->dev_channel, pb_len);
    async_send(data->client, data->dev_channel, pb, (int)pb_len, data->device_cfg.qos);
    data->device_cfg.last_send = time(NULL);
    free(pb);
}

static void send_hardware_info(Mqtt_data *data) {
    if (!data->device_cfg.enabled || !data->client_auth_received) return;

    char json_buf[512] = {0};
    get_hardware_info_json(json_buf, sizeof(json_buf), data->dev_uuid);

    size_t pb_len = 0;
    uint8_t *pb = pb_encode_sensor_data(data->dev_uuid, "hardware", json_buf, &pb_len);
    if (!pb) return;

    log_message("[CLIENT] Sending HARDWARE info to %s (pb)", data->dev_channel);
    async_send(data->client, data->dev_channel, pb, (int)pb_len, data->device_cfg.qos);
    free(pb);
}

static void send_network_info(Mqtt_data *data) {
    if (!data->network_cfg.enabled || !data->client_auth_received) return;

    char json_buf[512] = {0};
    get_network_info_json(json_buf, sizeof(json_buf), data->dev_uuid);

    size_t pb_len = 0;
    uint8_t *pb = pb_encode_sensor_data(data->dev_uuid, "network", json_buf, &pb_len);
    if (!pb) return;

    log_message("[CLIENT] Sending NETWORK info to %s (pb)", data->net_channel);
    async_send(data->client, data->net_channel, pb, (int)pb_len, data->network_cfg.qos);
    data->network_cfg.last_send = time(NULL);
    free(pb);
}

static void send_log_info(Mqtt_data *data) {
    if (!data->log_cfg.enabled || !data->client_auth_received) return;

    char json_buf[512] = {0};
    get_log_info_json(json_buf, sizeof(json_buf), data->dev_uuid);

    size_t pb_len = 0;
    uint8_t *pb = pb_encode_sensor_data(data->dev_uuid, "log", json_buf, &pb_len);
    if (!pb) return;

    log_message("[CLIENT] Sending LOG info to %s (pb)", data->log_channel);
    async_send(data->client, data->log_channel, pb, (int)pb_len, data->log_cfg.qos);
    data->log_cfg.last_send = time(NULL);
    free(pb);
}

/* ==================== 发送所有已启用消息 ==================== */
static void send_all_enabled_msgs(Mqtt_data *data, int initial) {
    if (initial) {
        /* 首次发送，立即发送一次 */
        if (data->device_cfg.enabled) {
            send_device_info(data);
            send_hardware_info(data);
        }
        if (data->network_cfg.enabled) send_network_info(data);
        if (data->log_cfg.enabled) send_log_info(data);
    } else {
        /* 定时检查发送 */
        time_t now = time(NULL);

        if (data->device_cfg.enabled && data->device_cfg.interval > 0) {
            if (now - data->device_cfg.last_send >= data->device_cfg.interval) {
                send_device_info(data);
            }
        }

        if (data->network_cfg.enabled && data->network_cfg.interval > 0) {
            if (now - data->network_cfg.last_send >= data->network_cfg.interval) {
                send_network_info(data);
            }
        }

        if (data->log_cfg.enabled && data->log_cfg.interval > 0) {
            if (now - data->log_cfg.last_send >= data->log_cfg.interval) {
                send_log_info(data);
            }
        }
    }
}

/* ==================== Epoll超时机制 ==================== */
/* 计算下次超时时间（毫秒），返回距离下次发送的最小时间 */
static int get_next_timeout_ms(Mqtt_data *data) {
    if (!data || !data->client_auth_received) {
        return 1000;  /* 默认1秒检查一次 */
    }

    time_t now = time(NULL);
    int min_timeout = 1000;  /* 默认最大1秒 */

    if (data->device_cfg.enabled && data->device_cfg.interval > 0) {
        int elapsed = now - data->device_cfg.last_send;
        int remaining = data->device_cfg.interval - elapsed;
        if (remaining <= 0) {
            return 0;  /* 立即发送 */
        }
        if (remaining < min_timeout) {
            min_timeout = remaining;
        }
    }

    if (data->network_cfg.enabled && data->network_cfg.interval > 0) {
        int elapsed = now - data->network_cfg.last_send;
        int remaining = data->network_cfg.interval - elapsed;
        if (remaining <= 0) {
            return 0;
        }
        if (remaining < min_timeout) {
            min_timeout = remaining;
        }
    }

    if (data->log_cfg.enabled && data->log_cfg.interval > 0) {
        int elapsed = now - data->log_cfg.last_send;
        int remaining = data->log_cfg.interval - elapsed;
        if (remaining <= 0) {
            return 0;
        }
        if (remaining < min_timeout) {
            min_timeout = remaining;
        }
    }

    return min_timeout * 1000;  /* 转换为毫秒 */
}

/* epoll超时时检查并发送各类型消息 */
static void handle_epoll_timeout(void) {
    if (!g_mqtt_data || !g_mqtt_data->client_auth_received) return;

    time_t now = time(NULL);

    if (g_mqtt_data->device_cfg.enabled && g_mqtt_data->device_cfg.interval > 0) {
        if (now - g_mqtt_data->device_cfg.last_send >= g_mqtt_data->device_cfg.interval) {
            send_device_info(g_mqtt_data);
            send_hardware_info(g_mqtt_data);
        }
    }

    if (g_mqtt_data->network_cfg.enabled && g_mqtt_data->network_cfg.interval > 0) {
        if (now - g_mqtt_data->network_cfg.last_send >= g_mqtt_data->network_cfg.interval) {
            send_network_info(g_mqtt_data);
        }
    }

    if (g_mqtt_data->log_cfg.enabled && g_mqtt_data->log_cfg.interval > 0) {
        if (now - g_mqtt_data->log_cfg.last_send >= g_mqtt_data->log_cfg.interval) {
            send_log_info(g_mqtt_data);
        }
    }
}

/* ==================== MQTT回调函数 ==================== */
void onDisconnectFailure(void* context, MQTTAsync_failureData* response) {
    (void)context;
    log_message("Disconnect failed, rc %d", response->code);
    sub_disc_finished = 1;
}

void onDisconnect(void* context, MQTTAsync_successData* response) {
    (void)context;
    (void)response;
    log_message("Successful disconnection");
    sub_disc_finished = 1;
}

void onSubscribe(void* context, MQTTAsync_successData* response) {
    (void)context;
    (void)response;
    log_message("Subscribe succeeded");
    sub_subscribed = 1;
}

void onSubscribeFailure(void* context, MQTTAsync_failureData* response) {
    (void)context;
    log_message("Subscribe failed, rc %d", response->code);
    sub_finished = 1;
}

void mqtt_onConnectFailure(void* context, MQTTAsync_failureData* response) {
    (void)context;
    log_message("========== CONNECT FAILURE ==========");
    log_message("Connect failed, rc %d", response ? response->code : -1);
    sub_finished = 1;
}

void mqtt_onConnect(void* context, MQTTAsync_successData* response) {
    (void)response;
    Mqtt_data *data = (Mqtt_data *)context;
    MQTTAsync client = data->client;
    MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
    int rc;

    log_message("========== CONNECT SUCCESS ==========");
    log_message("[%s] Connected to MQTT broker: %s",
                (data->flag == CLOUD_FLAG)?"cloud":"client", data->address);
    log_message("[%s] Client ID: %s",
                (data->flag == CLOUD_FLAG)?"cloud":"client", data->clientid);
    log_message("[%s] Subscribing to topic: %s (QoS %d)",
                (data->flag == CLOUD_FLAG)?"cloud":"client", data->topic, data->auth_qos);

    opts.onSuccess = onSubscribe;
    opts.onFailure = onSubscribeFailure;
    opts.context = context;
    /* 注意：opts 已被 Paho 库内部复制，此处不保存其局部地址 */
    if ((rc = MQTTAsync_subscribe(client, data->topic, data->auth_qos, &opts)) != MQTTASYNC_SUCCESS) {
        log_message("Failed to subscribe to %s, rc=%d", data->topic, rc);
        sub_finished = 1;
    } else {
        log_message("Subscribe request sent to %s", data->topic);
    }

    if (data->flag == CLIENT_FLAG) {
        log_message("========== CLIENT MODE ==========");
        log_message("[CLIENT] Connected to MQTT broker, waiting for auth command...");
        log_message("[CLIENT] Subscribed topic: cloud/#");
        if (data->client_auth_received) {
            log_message("[CLIENT] Auth already received, sending data immediately...");
            send_all_enabled_msgs(data, 1);
        } else {
            log_message("[CLIENT] Auth request will be sent when triggered by plugin command");
        }
    } else {
        log_message("========== CLOUD MODE ==========");
        log_message("[CLOUD] Waiting for device auth requests on: %s", data->topic);
    }
}

void mqtt_connlost(void *context, char *cause) {
    Mqtt_data *data = (Mqtt_data *)context;
    MQTTAsync client = data->client;
    MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
    int rc;

    log_message("========== CONNECTION LOST ==========");
    log_message("[%s] Connection lost!", data->flag == CLOUD_FLAG?"cloud":"client");
    if (cause) {
        log_message("     cause: %s", cause);
    }

    log_message("Reconnecting...");
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 0;
    conn_opts.onSuccess = mqtt_onConnect;
    conn_opts.onFailure = mqtt_onConnectFailure;

    /* 重连时使用 static 避免 Paho 异步线程访问已释放的栈内存 */
    static MQTTAsync_SSLOptions ssl_opts = MQTTAsync_SSLOptions_initializer;
    /* 重置上一次重连可能残留的指针（struct_id/struct_version 不变） */
    ssl_opts.trustStore = NULL;
    ssl_opts.keyStore = NULL;
    ssl_opts.privateKey = NULL;
    ssl_opts.privateKeyPassword = NULL;
    ssl_opts.enabledCipherSuites = NULL;
    ssl_opts.ssl_error_cb = NULL;
    ssl_opts.ssl_error_context = NULL;
    ssl_opts.ssl_psk_cb = NULL;
    ssl_opts.ssl_psk_context = NULL;
    ssl_opts.enableServerCertAuth = 0;
    ssl_opts.sslVersion = 0;
    if (data->ca_cert[0]) {
        ssl_opts.trustStore = data->ca_cert;
        ssl_opts.enableServerCertAuth = 1;
    }
    if (data->use_cert_auth && data->client_cert[0] && data->client_key[0]) {
        ssl_opts.keyStore = data->client_cert;
        ssl_opts.privateKey = data->client_key;
    }
    ssl_opts.sslVersion = data->tls_version;
    if (data->username[0]) {
        conn_opts.username = data->username;
        conn_opts.password = data->password;
    }
    if (strncmp(data->address, "ssl://", 6) == 0) {
        conn_opts.ssl = &ssl_opts;
    }

    if ((rc = MQTTAsync_connect(client, &conn_opts)) != MQTTASYNC_SUCCESS) {
        log_message("Failed to start reconnect, return code %d", rc);
        sub_finished = 1;
    }
}

/* ==================== 云端消息处理 ==================== */
int cloud_dev_msg_subscribe(void *context) {
    int rc = 0;
    Mqtt_data *data = (Mqtt_data *)context;

    /* 使用独立的局部变量，不能依赖 data->conn_opts
       (它指向 mqtt_onConnect 的局部变量，早已出栈) */
    MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
    opts.onSuccess = onSubscribe;
    opts.onFailure = onSubscribeFailure;
    opts.context = context;

    /* 直接使用 cloud_msg_mqtt_handle 设置好的 dev_uuid */
    char topic_buf[256] = {0};
    snprintf(topic_buf, sizeof(topic_buf), "client/dev/%s/#",
             data->dev_uuid[0] ? data->dev_uuid : "+");

    log_message("cloud_dev_msg_subscribe: subscribing to %s", topic_buf);

    if ((rc = MQTTAsync_subscribe(data->client, topic_buf, data->auth_qos, &opts)) != MQTTASYNC_SUCCESS) {
        log_message("cloud_dev_msg_subscribe: failed, rc=%d", rc);
    }

    log_message("cloud_dev_msg_subscribe: subscribed to %s for QoS%d", topic_buf, data->auth_qos);
    return rc;
}

/* 保存设备上报的数据到文件 (payload为protobuf二进制) */
static void cloud_store_device_data(const uint8_t *payload, int payloadlen) {
	/* Protobuf反序列化 */
	SensorData *sd = pb_decode_sensor_data(payload, (size_t)payloadlen);
	if (!sd) {
		log_message("cloud_store_device_data: protobuf decode failed");
		return;
	}

	const char *dev_uuid_str = sd->device_id ? sd->device_id : "";
	const char *type_str = sd->type ? sd->type : "device";
	const char *json_str = sd->payload_json ? sd->payload_json : "{}";

	log_message("cloud_store_device_data: uuid=%s, type=%s", dev_uuid_str, type_str);

	/* 解析payload_json为cJSON对象 */
	cJSON *json_obj = cJSON_Parse(json_str);
	if (!json_obj) json_obj = cJSON_CreateObject();

	/* 读取已有设备数据文件 */
	char data_file[320];
	snprintf(data_file, sizeof(data_file), "/tmp/cloud_device_%s.json", dev_uuid_str);

	cJSON *data_root = NULL;
	FILE *fp = fopen(data_file, "r");
	if (fp) {
		fseek(fp, 0, SEEK_END);
		long fsize = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		if (fsize > 0) {
			char *content = malloc(fsize + 1);
			if (content) {
				fread(content, 1, fsize, fp);
				content[fsize] = '\0';
				data_root = cJSON_Parse(content);
				free(content);
			}
		}
		fclose(fp);
	}
	if (!data_root) data_root = cJSON_CreateObject();

	/* 更新对应类型的数据 */
	cJSON_DeleteItemFromObject(data_root, type_str);
	cJSON_AddItemToObject(data_root, type_str, json_obj);

	/* 写回文件 */
	fp = fopen(data_file, "w");
	if (fp) {
		char *str = cJSON_Print(data_root);
		if (str) { fprintf(fp, "%s", str); free(str); }
		fclose(fp);
	}

	cJSON_Delete(data_root);
	sensor_data__free_unpacked(sd, NULL);
}

/* 保存云端已授权设备到文件 */

/* 从设备列表中删除设备 */
static void cloud_remove_device(const char *dev_uuid) {
	/* 删除设备数据文件 */
	char data_file[320];
	snprintf(data_file, sizeof(data_file), "/tmp/cloud_device_%s.json", dev_uuid);
	unlink(data_file);

	/* 从设备列表中移除 */
	const char *devices_file = "/tmp/cloud_devices.json";
	FILE *fp = fopen(devices_file, "r");
	if (!fp) return;

	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (fsize <= 0) { fclose(fp); return; }

	char *content = malloc(fsize + 1);
	if (!content) { fclose(fp); return; }
	fread(content, 1, fsize, fp);
	content[fsize] = '\0';
	fclose(fp);

	cJSON *root = cJSON_Parse(content);
	free(content);
	if (!root) return;

	cJSON *devices = cJSON_GetObjectItem(root, "devices");
	if (devices && cJSON_IsArray(devices)) {
		int idx = 0;
		cJSON *item;
		cJSON_ArrayForEach(item, devices) {
			cJSON *uuid = cJSON_GetObjectItem(item, "dev_uuid");
			if (uuid && uuid->valuestring && strcmp(uuid->valuestring, dev_uuid) == 0) {
				cJSON_DeleteItemFromArray(devices, idx);
				break;
			}
			idx++;
		}
	}

	fp = fopen(devices_file, "w");
	if (fp) {
		char *str = cJSON_Print(root);
		if (str) { fprintf(fp, "%s", str); free(str); }
		fclose(fp);
	}
	cJSON_Delete(root);
	log_message("cloud_remove_device: removed dev_uuid=%s", dev_uuid);
}
static void cloud_save_device(const char *dev_uuid, const char *data_types) {
	const char *devices_file = "/tmp/cloud_devices.json";
	cJSON *root = NULL;
	cJSON *devices = NULL;

	/* 先读取已有设备列表 */
	FILE *fp = fopen(devices_file, "r");
	if (fp) {
		fseek(fp, 0, SEEK_END);
		long fsize = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		if (fsize > 0) {
			char *content = malloc(fsize + 1);
			if (content) {
				fread(content, 1, fsize, fp);
				content[fsize] = '\0';
				root = cJSON_Parse(content);
				free(content);
			}
		}
		fclose(fp);
	}

	if (!root) root = cJSON_CreateObject();
	devices = cJSON_GetObjectItem(root, "devices");
	if (!devices) {
		devices = cJSON_CreateArray();
		cJSON_AddItemToObject(root, "devices", devices);
	}

	/* 检查是否已有该设备 */
	int found = 0;
	cJSON *item;
	cJSON_ArrayForEach(item, devices) {
		cJSON *uuid = cJSON_GetObjectItem(item, "dev_uuid");
		if (uuid && uuid->valuestring && strcmp(uuid->valuestring, dev_uuid) == 0) {
			found = 1;
			/* 更新数据 */
			cJSON_DeleteItemFromObject(item, "data_types");
			cJSON_AddStringToObject(item, "data_types", data_types ? data_types : "device");
			cJSON_DeleteItemFromObject(item, "auth_time");
			cJSON_AddNumberToObject(item, "auth_time", (double)time(NULL));
			cJSON_DeleteItemFromObject(item, "online");
			cJSON_AddNumberToObject(item, "online", 1);
			break;
		}
	}

	if (!found) {
		item = cJSON_CreateObject();
		cJSON_AddStringToObject(item, "dev_uuid", dev_uuid);
		cJSON_AddStringToObject(item, "data_types", data_types ? data_types : "device");
		cJSON_AddNumberToObject(item, "auth_time", (double)time(NULL));
		cJSON_AddNumberToObject(item, "online", 1);
		cJSON_AddItemToArray(devices, item);
	}

	/* 写回文件 */
	fp = fopen(devices_file, "w");
	if (fp) {
		char *str = cJSON_Print(root);
		if (str) {
			fprintf(fp, "%s", str);
			free(str);
		}
		fclose(fp);
		log_message("cloud_save_device: saved dev_uuid=%s to %s", dev_uuid, devices_file);
	}
	cJSON_Delete(root);
}
int cloud_msg_mqtt_handle(void *context, MQTTAsync_message *message) {
    char *payload = (char *)message->payload;
    int payloadlen = message->payloadlen;
    (void)payloadlen;
    int ret = 0;
    char authorize_str[21] = {0};
    char *tmp = NULL;
    char dev_uuid_buf[64] = {0};
    char types_str[64] = "device";

    Mqtt_data *data = (Mqtt_data *)context;
    data->type = 1;

    /* 先解析认证请求，提取 dev_uuid 和 upload_types */
    cJSON *auth_root = cJSON_Parse(payload);
    int is_test = 0;
    if (auth_root) {
        /* 检查是否为连通性测试 */
        cJSON *test_flag = cJSON_GetObjectItem(auth_root, "test");
        if (test_flag && cJSON_IsTrue(test_flag)) is_test = 1;

        cJSON *dev_uuid = cJSON_GetObjectItem(auth_root, "dev_uuid");
        cJSON *upload_types = cJSON_GetObjectItem(auth_root, "upload_types");
        if (dev_uuid && dev_uuid->valuestring) {
            strncpy(dev_uuid_buf, dev_uuid->valuestring, sizeof(dev_uuid_buf) - 1);
            strncpy(data->dev_uuid, dev_uuid->valuestring, sizeof(data->dev_uuid) - 1);
            data->dev_uuid[sizeof(data->dev_uuid) - 1] = '\0';
        }
        if (upload_types && cJSON_IsArray(upload_types)) {
            types_str[0] = '\0';
            cJSON *type_item;
            cJSON_ArrayForEach(type_item, upload_types) {
                if (type_item->valuestring) {
                    if (types_str[0]) strcat(types_str, ",");
                    strncat(types_str, type_item->valuestring, sizeof(types_str) - strlen(types_str) - 1);
                }
            }
            if (!types_str[0]) strcpy(types_str, "device");
        }
    }

    /* 连通性测试：不创建通道/不保存设备，直接返回结果 */
    if (is_test) {
        log_message("========================================");
        log_message("[TEST-CLOUD] 收到连通性测试请求");
        log_message("[TEST-CLOUD] 设备UUID: %s", dev_uuid_buf[0] ? dev_uuid_buf : "(未知)");
        log_message("[TEST-CLOUD] 原始消息: %.*s", payloadlen, payload);
        log_message("[TEST-CLOUD] 验证设备信息...");

        cJSON *test_resp = cJSON_CreateObject();
        cJSON_AddBoolToObject(test_resp, "test_ok", 1);
        cJSON_AddStringToObject(test_resp, "msg", "连接成功");
        cJSON_AddStringToObject(test_resp, "dev_uuid", dev_uuid_buf[0] ? dev_uuid_buf : "unknown");

        char test_topic[256];
        snprintf(test_topic, sizeof(test_topic), "cloud/%s/test",
                 dev_uuid_buf[0] ? dev_uuid_buf : "unknown");

        char *resp_str = cJSON_PrintUnformatted(test_resp);
        async_send_str(data->client, test_topic, resp_str, data->auth_qos);
        log_message("[TEST-CLOUD] 测试结果已发布到 %s (QoS=%d): %s",
                   test_topic, data->auth_qos, resp_str);
        log_message("[TEST-CLOUD] ✓ 连通性测试通过");
        log_message("========================================");

        free(resp_str);
        cJSON_Delete(test_resp);
        if (auth_root) cJSON_Delete(auth_root);
        return 0;  /* 测试模式完成，跳过正常认证流程 */
    }

    if (auth_root) cJSON_Delete(auth_root);

    log_message("[AUTH-CLOUD] ===== 开始处理认证请求 =====");
    log_message("[AUTH-CLOUD] dev_uuid=%s, types=%s", dev_uuid_buf, types_str);

    mqtt_generate_random_string(authorize_str, 20);
    log_message("[AUTH-CLOUD] 生成随机通道ID: %s", authorize_str);

    /* 三个独立通道 */
    char dev_ch[256], net_ch[256], log_ch[256];
    snprintf(dev_ch, sizeof(dev_ch), "client/dev/%s", authorize_str);
    snprintf(net_ch, sizeof(net_ch), "client/net/%s", authorize_str);
    snprintf(log_ch, sizeof(log_ch), "client/log/%s", authorize_str);
    log_message("[AUTH-CLOUD] 通道分配: dev=%s, net=%s, log=%s", dev_ch, net_ch, log_ch);

    /* 更新全局client_topic(兼容) */
    strncpy(client_topic, dev_ch, sizeof(client_topic) - 1);

    /* 订阅通配符通道以接收所有设备数据 */
    {
        MQTTAsync_responseOptions sub_opts = MQTTAsync_responseOptions_initializer;
        sub_opts.onSuccess = onSubscribe;
        sub_opts.onFailure = onSubscribeFailure;
        sub_opts.context = context;

        MQTTAsync_subscribe(data->client, "client/dev/#", data->auth_qos, &sub_opts);
        MQTTAsync_subscribe(data->client, "client/net/#", data->auth_qos, &sub_opts);
        MQTTAsync_subscribe(data->client, "client/log/#", data->auth_qos, &sub_opts);
        log_message("[AUTH-CLOUD] 已订阅通配符: client/dev/#, client/net/#, client/log/# (QoS=%d)", data->auth_qos);
    }

    /* 保存设备到列表 */
    if (dev_uuid_buf[0]) {
        cloud_save_device(dev_uuid_buf, types_str);
        log_message("[AUTH-CLOUD] 设备已保存: %s, types=%s", dev_uuid_buf, types_str);
    } else {
        log_message("[AUTH-CLOUD] 警告: dev_uuid 为空，未保存设备");
    }

    /* 发送授权消息(包含三个独立通道) */
    char auth_reply[1024] = {0};
    snprintf(auth_reply, sizeof(auth_reply),
        "{\"authorized\":true,\"dev_channel\":\"%s\",\"net_channel\":\"%s\",\"log_channel\":\"%s\"}",
        dev_ch, net_ch, log_ch);

    log_message("[AUTH-CLOUD] 授权响应内容: %s", auth_reply);
    tmp = mqtt_config_read_string("cloud_pub_topic");
    if (tmp) {
        async_send_str(data->client, tmp, auth_reply, data->auth_qos);
        log_message("[AUTH-CLOUD] 授权响应已发布到 %s (QoS=%d)", tmp, data->auth_qos);
        log_message("[AUTH-CLOUD] ===== 认证处理完成 =====");
        free(tmp);
    } else {
        log_message("[AUTH-CLOUD] ✗ 无法读取 cloud_pub_topic，授权响应未发送!");
    }

    return ret;
}

/* ==================== 设备端消息处理 ==================== */
int client_msg_mqtt_handle(void *context, MQTTAsync_message *message) {
    Mqtt_data *data = (Mqtt_data *)context;
    cJSON *root = NULL;
    char *payload = (char *)message->payload;
    int payloadlen = message->payloadlen;

    log_message("[AUTH-CLIENT] 收到消息 (topic在回调中): %.*s", payloadlen, payload);

    root = cJSON_Parse(payload);
    if (!root) {
        log_message("[AUTH-CLIENT] JSON 解析失败");
        return 0;
    }

    /* 连通性测试结果: {test_ok:true, msg:"..."} → 写入文件供 plugin 读取 */
    cJSON *test_ok = cJSON_GetObjectItem(root, "test_ok");
    if (test_ok) {
        int ok = cJSON_IsTrue(test_ok) ? 1 : 0;
        cJSON *test_msg = cJSON_GetObjectItem(root, "msg");
        log_message("========================================");
        log_message("[TEST-CLIENT] 收到测试结果!");
        log_message("[TEST-CLIENT] 结果: %s", ok ? "✓ 成功" : "✗ 失败");
        log_message("[TEST-CLIENT] 详情: %s", (test_msg && test_msg->valuestring) ? test_msg->valuestring : "(无)");

        /* 写入测试结果文件 */
        mkdir("/data/work", 0755);
        FILE *fp = fopen("/data/work/mqtt_test_result.json", "w");
        if (fp) {
            char *result_str = cJSON_PrintUnformatted(root);
            if (result_str) {
                fprintf(fp, "%s", result_str);
                free(result_str);
                log_message("[TEST-CLIENT] 测试结果已写入文件");
            }
            fclose(fp);
        } else {
            log_message("[TEST-CLIENT] ✗ 无法写入结果文件!");
        }
        log_message("========================================");
        cJSON_Delete(root);
        return 0;
    }

    cJSON *authorized = cJSON_GetObjectItem(root, "authorized");
    log_message("[AUTH-CLIENT] authorized=%s",
                (authorized && cJSON_IsTrue(authorized)) ? "true" : "false/missing");
    /* 新格式: dev_channel / net_channel / log_channel */
    cJSON *dev_ch = cJSON_GetObjectItem(root, "dev_channel");
    cJSON *net_ch = cJSON_GetObjectItem(root, "net_channel");
    cJSON *log_ch = cJSON_GetObjectItem(root, "log_channel");

    if (authorized && authorized->type == cJSON_True) {
        if (!data->client_auth_received) {
            /* 保存三个独立通道 */
            if (dev_ch && dev_ch->valuestring) {
                strncpy(data->dev_channel, dev_ch->valuestring, sizeof(data->dev_channel) - 1);
                strncpy(data->auth_channel, dev_ch->valuestring, sizeof(data->auth_channel) - 1);
            }
            if (net_ch && net_ch->valuestring) {
                strncpy(data->net_channel, net_ch->valuestring, sizeof(data->net_channel) - 1);
            }
            if (log_ch && log_ch->valuestring) {
                strncpy(data->log_channel, log_ch->valuestring, sizeof(data->log_channel) - 1);
            }
            data->client_auth_received = 1;

            /* 保存到配置文件 */
            save_auth_channel(data->dev_channel);
            write_client_auth_status(1);

            log_message("client_msg_mqtt_handle: Auth complete, dev=%s, net=%s, log=%s",
                       data->dev_channel, data->net_channel, data->log_channel);

            /* 立即发送一次所有已启用的消息类型 */
            send_all_enabled_msgs(data, 1);
        } else {
            log_message("client_msg_mqtt_handle: Auth already received, ignoring duplicate");
        }
    }

    cJSON_Delete(root);
    return 0;
}

/* ==================== 消息到达回调 ==================== */
int mqtt_msgarrvd(void *context, char *topicName, int topicLen, MQTTAsync_message *message) {
    (void)topicLen;
    log_message("========== MESSAGE RECEIVED ==========");
    log_message("[%s] Topic: %s", mqtt_usr, topicName);
    log_message("[%s] Payload (%d bytes): %.*s", mqtt_usr, message->payloadlen,
               message->payloadlen, (char*)message->payload);

    Mqtt_data* mqtt_data = (Mqtt_data *)context;
    int ret = 0;

    if (strncmp(mqtt_usr, "cloud", strlen(mqtt_usr)) == 0) {
        log_message("[CLOUD] mqtt_data->type=%d, topic=%s", mqtt_data->type, topicName);

        /* 优先检测是否为 JSON 格式的 auth/test/stop 消息 */
        cJSON *first_check = cJSON_Parse((char*)message->payload);
        int is_auth_msg = 0;
        int is_test_msg = 0;
        int is_stop_msg = 0;
        if (first_check) {
            if (cJSON_GetObjectItem(first_check, "auth_request")) is_auth_msg = 1;
            if (cJSON_GetObjectItem(first_check, "test"))         is_test_msg  = 1;
            if (cJSON_GetObjectItem(first_check, "device_stop"))  is_stop_msg  = 1;
            cJSON_Delete(first_check);
        }

        if (is_auth_msg || is_test_msg || (mqtt_data->type != 1)) {
            log_message("[CLOUD] Handling auth/test request (auth=%d, test=%d, type=%d)",
                       is_auth_msg, is_test_msg, mqtt_data->type);
            ret = cloud_msg_mqtt_handle(context, message);
        } else if (is_stop_msg) {
            /* 设备停止通知 */
            cJSON *stop_root = cJSON_Parse((char*)message->payload);
            if (stop_root) {
                cJSON *uuid = cJSON_GetObjectItem(stop_root, "dev_uuid");
                if (uuid && uuid->valuestring) {
                    log_message("[CLOUD] Device stop notification (json): %s", uuid->valuestring);
                    cloud_remove_device(uuid->valuestring);
                }
                cJSON_Delete(stop_root);
            }
        } else {
            /* 数据消息：尝试protobuf解码 */
            log_message("[CLOUD] Data message, len=%d, topic=%s", message->payloadlen, topicName);

            SensorData *sd = pb_decode_sensor_data((const uint8_t*)message->payload,
                                                    (size_t)message->payloadlen);
            if (sd) {
                if (sd->type && strcmp(sd->type, "device_stop") == 0) {
                    log_message("[CLOUD] Device stop notification (pb): %s",
                               sd->device_id ? sd->device_id : "");
                    cloud_remove_device(sd->device_id);
                } else {
                    log_message("[CLOUD] Storing device data: type=%s, id=%s",
                               sd->type ? sd->type : "?", sd->device_id ? sd->device_id : "?");
                    cloud_store_device_data((const uint8_t*)message->payload, message->payloadlen);
                }
                sensor_data__free_unpacked(sd, NULL);
            } else {
                log_message("[CLOUD] Unrecognized message format on topic %s", topicName);
            }
        }
    } else {
        log_message("[CLIENT] Handling message...");
        ret = client_msg_mqtt_handle(context, message);
    }

    MQTTAsync_freeMessage(&message);
    MQTTAsync_free(topicName);
    if (ret != 0) {
        sub_finished = 1;
    }
    return 1;
}

/* ==================== 主循环 ==================== */
int mqtt_msg_handle(Context *file_data) {
    MQTTAsync client;
    MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
    MQTTAsync_disconnectOptions disc_opts = MQTTAsync_disconnectOptions_initializer;
    int rc = 0;

    Mqtt_data *mqtt_data = (Mqtt_data*)calloc(1, sizeof(Mqtt_data));
    mqtt_usr = (file_data->flag == CLOUD_FLAG) ? "cloud" : "client";

    log_message("========== MQTT MSG HANDLE START ==========");
    log_message("[%s] Initializing MQTT client...", mqtt_usr);
    log_message("[%s] Broker: %s", mqtt_usr, file_data->address);

    mqtt_data->fd = file_data->fd;
    mqtt_data->auth_qos = file_data->auth_qos;

    /* 各消息类型配置初始化 */
    mqtt_data->device_cfg.qos = file_data->device_qos;
    mqtt_data->device_cfg.interval = file_data->send_interval;
    mqtt_data->device_cfg.enabled = 1;
    mqtt_data->device_cfg.last_send = 0;

    mqtt_data->network_cfg.qos = file_data->network_qos;
    mqtt_data->network_cfg.interval = 30;
    mqtt_data->network_cfg.enabled = 1;
    mqtt_data->network_cfg.last_send = 0;

    mqtt_data->log_cfg.qos = file_data->log_qos;
    mqtt_data->log_cfg.interval = 60;
    mqtt_data->log_cfg.enabled = 1;
    mqtt_data->log_cfg.last_send = 0;

    log_message("[CLIENT] device_cfg: [qos=%d, interval=%d]", mqtt_data->device_cfg.qos, mqtt_data->device_cfg.interval);
    log_message("[CLIENT] network_cfg: [qos=%d, interval=%d]", mqtt_data->network_cfg.qos, mqtt_data->network_cfg.interval);
    log_message("[CLIENT] log_cfg: [qos=%d, interval=%d]", mqtt_data->log_cfg.qos, mqtt_data->log_cfg.interval);

    SAFE_STRCPY(mqtt_data->address, file_data->address, sizeof(mqtt_data->address));
    SAFE_STRCPY(mqtt_data->pub_clientid, file_data->pub_clientid, sizeof(mqtt_data->pub_clientid));
    SAFE_STRCPY(mqtt_data->pub_topic, file_data->pub_topic, sizeof(mqtt_data->pub_topic));

    switch (file_data->flag) {
        case CLOUD_FLAG:
            mqtt_data->type = 0;
            mqtt_data->flag = CLOUD_FLAG;
            SAFE_STRCPY(mqtt_data->clientid, file_data->cloud_sub_clientid, sizeof(mqtt_data->clientid));
            SAFE_STRCPY(mqtt_data->topic, file_data->cloud_sub_topic, sizeof(mqtt_data->topic));
            log_message("[CLOUD] Mode: CLOUD_FLAG");
            log_message("[CLOUD] Client ID: %s", file_data->cloud_sub_clientid);
            log_message("[CLOUD] Subscribe topic: %s", file_data->cloud_sub_topic);
            break;
        case CLIENT_FLAG:
            mqtt_data->flag = CLIENT_FLAG;
            {
                size_t len = strlen(file_data->sub_clientid);
                memcpy(mqtt_data->clientid, file_data->sub_clientid, len < MAX_CLIENTID_LEN ? len : MAX_CLIENTID_LEN - 1);
                mqtt_data->clientid[MAX_CLIENTID_LEN - 1] = '\0';
            }
            {
                size_t len = strlen(file_data->sub_topic);
                memcpy(mqtt_data->topic, file_data->sub_topic, len < MAX_TOPIC_LEN ? len : MAX_TOPIC_LEN - 1);
                mqtt_data->topic[MAX_TOPIC_LEN - 1] = '\0';
            }
            {
                size_t len = strlen(file_data->dev_uuid);
                memcpy(mqtt_data->dev_uuid, file_data->dev_uuid, len < MAX_TOPIC_LEN ? len : MAX_TOPIC_LEN - 1);
                mqtt_data->dev_uuid[MAX_TOPIC_LEN - 1] = '\0';
            }

            /* 检查是否已有保存的 auth_channel（重启后恢复） */
            {
                char *saved_channel = mqtt_config_read_string("auth_channel");
                if (saved_channel && strlen(saved_channel) > 0) {
                    strncpy(mqtt_data->auth_channel, saved_channel, sizeof(mqtt_data->auth_channel) - 1);
                    mqtt_data->auth_channel[sizeof(mqtt_data->auth_channel) - 1] = '\0';
                    mqtt_data->client_auth_received = 1;
                    write_client_auth_status(1);
                    log_message("[CLIENT] Restored auth_channel from config: %s", mqtt_data->auth_channel);
                }
                if (saved_channel) free(saved_channel);
            }

            log_message("[CLIENT] Mode: CLIENT_FLAG");
            log_message("[CLIENT] Client ID: %s", file_data->sub_clientid);
            log_message("[CLIENT] Subscribe topic: %s", file_data->sub_topic);
            log_message("[CLIENT] Dev UUID: %s", file_data->dev_uuid);
            if (mqtt_data->client_auth_received) {
                log_message("[CLIENT] Auth already received, channel: %s", mqtt_data->auth_channel);
            }
            break;
        default:
            sub_finished = 1;
            break;
    }

    log_message("\n%s_json_file_messege:\n\tbroker address:%s\n\tauth_sub_clientid:%s\n\tauth_sub_topic:%s\n\tauth_qos:%d\n",
        (file_data->flag == CLOUD_FLAG)?"cloud":"client", mqtt_data->address,
        mqtt_data->clientid, mqtt_data->topic, mqtt_data->auth_qos);

    if ((rc = MQTTAsync_create(&client, mqtt_data->address, mqtt_data->clientid,
                               MQTTCLIENT_PERSISTENCE_NONE, NULL)) != MQTTASYNC_SUCCESS) {
        log_message("Failed to create client, return code %d", rc);
        rc = EXIT_FAILURE;
        goto exit;
    }

    if ((rc = MQTTAsync_setCallbacks(client, mqtt_data, mqtt_connlost, mqtt_msgarrvd, NULL)) != MQTTASYNC_SUCCESS) {
        log_message("Failed to set callbacks, return code %d", rc);
        rc = EXIT_FAILURE;
        goto destroy_exit;
    }

    mqtt_data->client = client;

    /* 复制TLS/认证配置到 mqtt_data (重连时使用) */
    strncpy(mqtt_data->ca_cert, file_data->ca_cert, sizeof(mqtt_data->ca_cert) - 1);
    strncpy(mqtt_data->client_cert, file_data->client_cert, sizeof(mqtt_data->client_cert) - 1);
    strncpy(mqtt_data->client_key, file_data->client_key, sizeof(mqtt_data->client_key) - 1);
    strncpy(mqtt_data->username, file_data->username, sizeof(mqtt_data->username) - 1);
    strncpy(mqtt_data->password, file_data->password, sizeof(mqtt_data->password) - 1);
    mqtt_data->use_cert_auth = file_data->use_cert_auth;
    mqtt_data->tls_version = file_data->tls_version;
    strncpy(mqtt_data->address, file_data->address, sizeof(mqtt_data->address) - 1);

    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;
    conn_opts.onSuccess = mqtt_onConnect;
    conn_opts.onFailure = mqtt_onConnectFailure;
    conn_opts.context = mqtt_data;

    /* TLS/SSL 配置 */
    MQTTAsync_SSLOptions ssl_opts = MQTTAsync_SSLOptions_initializer;
    if (file_data->ca_cert[0]) {
        ssl_opts.trustStore = file_data->ca_cert;
        ssl_opts.enableServerCertAuth = 1;
    }
    if (file_data->use_cert_auth && file_data->client_cert[0] && file_data->client_key[0]) {
        ssl_opts.keyStore = file_data->client_cert;
        ssl_opts.privateKey = file_data->client_key;
        log_message("[%s] Using client certificate authentication", mqtt_usr);
    }
    ssl_opts.sslVersion = file_data->tls_version;

    /* 用户名密码认证 */
    if (file_data->username[0]) {
        conn_opts.username = file_data->username;
        conn_opts.password = file_data->password;
        log_message("[%s] Using username/password authentication", mqtt_usr);
    }

    /* 如果是ssl://地址，启用TLS */
    if (strncmp(file_data->address, "ssl://", 6) == 0) {
        conn_opts.ssl = &ssl_opts;
        log_message("[%s] TLS enabled for %s", mqtt_usr, file_data->address);
    }

    if ((rc = MQTTAsync_connect(client, &conn_opts)) != MQTTASYNC_SUCCESS) {
        log_message("Failed to start connect, return code %d", rc);
        rc = EXIT_FAILURE;
        goto destroy_exit;
    }

    while (!sub_subscribed && !sub_finished) {
        usleep(10000L);
    }

    if (sub_finished) {
        goto exit;
    }

    /* CLIENT 模式下设置全局数据指针 */
    if (file_data->flag == CLIENT_FLAG) {
        g_mqtt_data = mqtt_data;
    }

    /* 主循环使用 epoll */
    int epoll_fd;
    struct epoll_event ev, events[2];
    char cmd_buf[256] = {0};
    int cmd_fd = file_data->fd;      /* 数据管道 */
    int plugin_fd = file_data->cmd_fd;  /* 命令管道 (plugin命令) */

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        log_message("mqtt_msg_handle: epoll_create1 failed");
        goto exit;
    }

    ev.events = EPOLLIN;
    ev.data.fd = cmd_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cmd_fd, &ev) < 0) {
        log_message("mqtt_msg_handle: epoll_ctl failed");
        close(epoll_fd);
        goto exit;
    }

    /* CLIENT模式：添加命令管道监听，接收plugin命令 */
    if (file_data->flag == CLIENT_FLAG && plugin_fd >= 0) {
        ev.events = EPOLLIN;
        ev.data.fd = plugin_fd;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, plugin_fd, &ev) < 0) {
            log_message("mqtt_msg_handle: epoll_ctl add plugin_fd failed");
        } else {
            log_message("mqtt_msg_handle: added plugin_fd=%d to epoll", plugin_fd);
        }
    }

    log_message("========== MAIN LOOP STARTED ==========");
    log_message("[%s] MQTT client running, waiting for messages...", mqtt_usr);
    log_message("[%s] Subscribed topic: %s", mqtt_usr, mqtt_data->topic);

    while (!sub_finished && file_data->running) {
        int timeout_ms = (file_data->flag == CLIENT_FLAG) ? get_next_timeout_ms(mqtt_data) : 1000;

        int nfds = epoll_wait(epoll_fd, events, 2, timeout_ms);

        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (nfds == 0) {
            /* 超时，检查定时发送 */
            if (file_data->flag == CLIENT_FLAG) {
                handle_epoll_timeout();
            }
            continue;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == plugin_fd && file_data->flag == CLIENT_FLAG) {
                /* 收到plugin命令 */
                MqttCmd plugin_cmd;
                int len = read(plugin_fd, &plugin_cmd, sizeof(plugin_cmd));
                if (len == sizeof(plugin_cmd)) {
                    log_message("[CLIENT] Received plugin command: type=%d, data=%s",
                               plugin_cmd.cmd_type, plugin_cmd.data);

                    if (plugin_cmd.cmd_type == CMD_DEVICE_AUTH) {
                        /* 发送认证请求 - 解析前端传来的实际数据类型和设备UUID */
                        log_message("[CLIENT] Sending auth request to %s", mqtt_data->pub_topic);

                        /* 解析plugin传来的JSON获取data_types和dev_uuid */
                        cJSON *auth_cfg = cJSON_Parse(plugin_cmd.data);
                        char types_str[64] = "device";  /* device默认必选 */
                        if (auth_cfg) {
                            /* 更新设备UUID（使用前端从/sys/class/dmi/id/product_uuid读取的真实UUID） */
                            cJSON *cfg_uuid = cJSON_GetObjectItem(auth_cfg, "dev_uuid");
                            if (cfg_uuid && cfg_uuid->valuestring) {
                                strncpy(mqtt_data->dev_uuid, cfg_uuid->valuestring,
                                        sizeof(mqtt_data->dev_uuid) - 1);
                                mqtt_data->dev_uuid[sizeof(mqtt_data->dev_uuid) - 1] = '\0';
                                log_message("[CLIENT] Updated dev_uuid from frontend: %s",
                                           mqtt_data->dev_uuid);
                            }

                            /* 读取用户选择的数据类型 */
                            cJSON *cfg_types = cJSON_GetObjectItem(auth_cfg, "data_types");
                            if (cfg_types && cJSON_IsArray(cfg_types)) {
                                /* 先全部禁用，再按选择启用 */
                                mqtt_data->device_cfg.enabled = 0;
                                mqtt_data->network_cfg.enabled = 0;
                                mqtt_data->log_cfg.enabled = 0;

                                types_str[0] = '\0';
                                cJSON *type_item;
                                cJSON_ArrayForEach(type_item, cfg_types) {
                                    if (type_item->valuestring) {
                                        if (types_str[0]) strcat(types_str, ",");
                                        strncat(types_str, type_item->valuestring,
                                                sizeof(types_str) - strlen(types_str) - 1);

                                        if (strcmp(type_item->valuestring, "device") == 0)
                                            mqtt_data->device_cfg.enabled = 1;
                                        else if (strcmp(type_item->valuestring, "network") == 0)
                                            mqtt_data->network_cfg.enabled = 1;
                                        else if (strcmp(type_item->valuestring, "log") == 0)
                                            mqtt_data->log_cfg.enabled = 1;
                                    }
                                }
                                if (!types_str[0]) {
                                    /* 兜底：至少device */
                                    strcpy(types_str, "device");
                                    mqtt_data->device_cfg.enabled = 1;
                                }
                            }
                            cJSON_Delete(auth_cfg);
                        }

                        log_message("[CLIENT] Auth upload_types=%s, device=%d, network=%d, log=%d",
                                   types_str, mqtt_data->device_cfg.enabled,
                                   mqtt_data->network_cfg.enabled, mqtt_data->log_cfg.enabled);

                        /* 用cJSON构建正确的JSON auth消息 */
                        cJSON *auth_json = cJSON_CreateObject();
                        cJSON_AddBoolToObject(auth_json, "auth_request", 1);
                        cJSON_AddStringToObject(auth_json, "dev_uuid", mqtt_data->dev_uuid);
                        cJSON *upload_arr = cJSON_CreateArray();
                        if (mqtt_data->device_cfg.enabled)
                            cJSON_AddItemToArray(upload_arr, cJSON_CreateString("device"));
                        if (mqtt_data->network_cfg.enabled)
                            cJSON_AddItemToArray(upload_arr, cJSON_CreateString("network"));
                        if (mqtt_data->log_cfg.enabled)
                            cJSON_AddItemToArray(upload_arr, cJSON_CreateString("log"));
                        cJSON_AddItemToObject(auth_json, "upload_types", upload_arr);
                        char *auth_msg = cJSON_PrintUnformatted(auth_json);
                        async_send_str(mqtt_data->client, mqtt_data->pub_topic, auth_msg, mqtt_data->auth_qos);
                        log_message("[CLIENT] Auth request sent: %s", auth_msg);
                        free(auth_msg);
                        cJSON_Delete(auth_json);
                    } else if (plugin_cmd.cmd_type == CMD_DEVICE_TEST) {
                        /* ========== 连通性测试：客户端处理 ========== */
                        log_message("========================================");
                        log_message("[TEST-CLIENT] 收到连通性测试命令");
                        log_message("[TEST-CLIENT] 命令数据: %s", plugin_cmd.data);

                        cJSON *test_cfg = cJSON_Parse(plugin_cmd.data);
                        char test_uuid[64] = {0};
                        if (test_cfg) {
                            cJSON *u = cJSON_GetObjectItem(test_cfg, "dev_uuid");
                            if (u && u->valuestring) {
                                strncpy(test_uuid, u->valuestring, sizeof(test_uuid) - 1);
                                log_message("[TEST-CLIENT] 设备UUID: %s", test_uuid);
                            }
                            cJSON *addr = cJSON_GetObjectItem(test_cfg, "address");
                            if (addr && addr->valuestring)
                                log_message("[TEST-CLIENT] 目标地址: %s", addr->valuestring);
                            cJSON_Delete(test_cfg);
                        }
                        if (!test_uuid[0]) {
                            strncpy(test_uuid, mqtt_data->dev_uuid, sizeof(test_uuid) - 1);
                            log_message("[TEST-CLIENT] 使用默认UUID: %s", test_uuid);
                        }

                        /* 订阅测试结果通道 */
                        char test_topic[256];
                        snprintf(test_topic, sizeof(test_topic), "cloud/%s/test", test_uuid);
                        {
                            MQTTAsync_responseOptions sub_opts = MQTTAsync_responseOptions_initializer;
                            sub_opts.onSuccess = onSubscribe;
                            sub_opts.context = mqtt_data;
                            MQTTAsync_subscribe(mqtt_data->client, test_topic, mqtt_data->auth_qos, &sub_opts);
                            log_message("[TEST-CLIENT] 已订阅测试结果通道: %s (QoS=%d)",
                                       test_topic, mqtt_data->auth_qos);
                        }

                        /* 发布测试请求到 client/auth */
                        cJSON *test_json = cJSON_CreateObject();
                        cJSON_AddBoolToObject(test_json, "test", 1);
                        cJSON_AddStringToObject(test_json, "dev_uuid", test_uuid);
                        char *test_msg = cJSON_PrintUnformatted(test_json);
                        async_send_str(mqtt_data->client, mqtt_data->pub_topic, test_msg, mqtt_data->auth_qos);
                        log_message("[TEST-CLIENT] 测试请求已发布到 %s (QoS=%d): %s",
                                   mqtt_data->pub_topic, mqtt_data->auth_qos, test_msg);
                        log_message("[TEST-CLIENT] 等待云端响应于通道 %s ...", test_topic);
                        free(test_msg);
                        cJSON_Delete(test_json);
                        log_message("========================================");
                    } else if (plugin_cmd.cmd_type == CMD_DEVICE_STOP) {
                        /* 停止上报 */
                        log_message("[CLIENT] Received stop command, resetting auth state");
                        mqtt_data->client_auth_received = 0;
                        memset(mqtt_data->auth_channel, 0, sizeof(mqtt_data->auth_channel));
                        memset(mqtt_data->dev_channel, 0, sizeof(mqtt_data->dev_channel));
                        memset(mqtt_data->net_channel, 0, sizeof(mqtt_data->net_channel));
                        memset(mqtt_data->log_channel, 0, sizeof(mqtt_data->log_channel));
                        /* 清除认证状态文件 */
                        write_client_auth_status(0);
                        /* 清除保存的auth_channel */
                        save_auth_channel("");

                        /* 发送停止通知给云端，让云端删除该设备 */
                        cJSON *stop_json = cJSON_CreateObject();
                        cJSON_AddBoolToObject(stop_json, "device_stop", 1);
                        cJSON_AddStringToObject(stop_json, "dev_uuid", mqtt_data->dev_uuid);
                        char *stop_msg = cJSON_PrintUnformatted(stop_json);
                        async_send_str(mqtt_data->client, mqtt_data->pub_topic, stop_msg, mqtt_data->auth_qos);
                        log_message("[CLIENT] Sent device_stop notification to cloud: %s", stop_msg);
                        free(stop_msg);
                        cJSON_Delete(stop_json);

                        log_message("[CLIENT] Auth state cleared, data reporting stopped");
                    }
                }
            } else if (events[i].data.fd == cmd_fd) {
                /* 数据管道消息 */
                int len = read(cmd_fd, cmd_buf, sizeof(cmd_buf) - 1);
                if (len > 0) {
                    cmd_buf[len] = '\0';
                    log_message("Received command: %s", cmd_buf);

                    if (strncmp(cmd_buf, "stop", 4) == 0) {
                        log_message("Stop command received");
                        sub_finished = 1;
                        break;
                    } else if (strncmp(cmd_buf, "status", 6) == 0) {
                        char status_buf[128];
                        snprintf(status_buf, sizeof(status_buf), "status:running,flag:%s,auth:%d",
                                (file_data->flag == CLOUD_FLAG)?"cloud":"client", mqtt_data->client_auth_received);
                        if (write(cmd_fd, status_buf, strlen(status_buf)) < 0) {
                            log_message("mqtt_msg_handle: write status failed");
                        }
                    }
                }
            }
        }
    }

    close(epoll_fd);
    log_message("========== MAIN LOOP EXITING ==========");

    disc_opts.onSuccess = onDisconnect;
    disc_opts.onFailure = onDisconnectFailure;
    if ((rc = MQTTAsync_disconnect(client, &disc_opts)) != MQTTASYNC_SUCCESS) {
        log_message("Failed to start disconnect, rc=%d", rc);
        rc = EXIT_FAILURE;
        goto destroy_exit;
    }
    while (!sub_disc_finished) {
        usleep(10000L);
    }

destroy_exit:
    MQTTAsync_destroy(&client);
exit:
    log_message("========== PROCESS EXITED ==========");
    free(mqtt_data);
    return rc;
}

/* ==================== 异步发送 ==================== */
static int async_send(MQTTAsync client, const char *topic, const void *payload, int payloadlen, int qos) {
    MQTTAsync_message msg = MQTTAsync_message_initializer;
    msg.payload = (void *)payload;
    msg.payloadlen = payloadlen;
    msg.qos = qos;
    msg.retained = 0;

    MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
    int rc = MQTTAsync_sendMessage(client, topic, &msg, &opts);
    if (rc != MQTTASYNC_SUCCESS) {
        log_message("async_send FAILED to %s, rc=%d", topic, rc);
        return -1;
    }
    log_message("async_send OK to %s (qos=%d, len=%d)", topic, qos, payloadlen);
    return 0;
}

static int async_send_str(MQTTAsync client, const char *topic, const char *str, int qos) {
    return async_send(client, topic, str, (int)strlen(str), qos);
}