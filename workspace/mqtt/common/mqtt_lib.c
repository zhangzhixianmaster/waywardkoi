#include "mqtt_lib.h"
#include "mqtt_cmd.h"
#include <stdarg.h>
#include <stdlib.h>

/* ==================== 日志实现 ==================== */
void log_message_impl(const char *file, int line, const char *format, ...) {
    FILE *log_file = fopen(LOG_FILE_PATH, "a");
    if (log_file == NULL) return;

    time_t now;
    time(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    const char *base_file = strrchr(file, '/');
    base_file = base_file ? base_file + 1 : file;

    va_list args;
    va_start(args, format);
    fprintf(log_file, "[%s] [%s:%d] ", timestamp, base_file, line);
    vfprintf(log_file, format, args);
    fprintf(log_file, "\n");
    va_end(args);

    fclose(log_file);
}

/* ==================== 配置文件操作实现 ==================== */
/* CONFIG_FILE_PATH defined in mqtt_lib.h */

/* 静态变量：缓存解析后的 cJSON 根节点 */
static cJSON *g_config_root = NULL;

/* 全局变量：保存client进程的命令管道写端，供mqtt_cmd_handle使用 */
int g_client_cmd_fd = -1;

/**
 * 初始化配置（只打开一次文件）
 * 失败则直接退出程序
 */
static void config_init(void) {
    if (g_config_root != NULL) return;  /* 已初始化 */

    FILE *fp = fopen(CONFIG_FILE_PATH, "r");
    if (!fp) {
        log_message("FATAL: cannot open config file: %s", CONFIG_FILE_PATH);
        exit(1);
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *content = malloc(fsize + 1);
    if (!content) {
        log_message("FATAL: malloc failed");
        exit(1);
    }

    if (fread(content, 1, fsize, fp) != (size_t)fsize) {
        log_message("FATAL: fread incomplete");
        exit(1);
    }
    content[fsize] = '\0';
    fclose(fp);

    g_config_root = cJSON_Parse(content);
    free(content);

    if (!g_config_root) {
        log_message("FATAL: cJSON_Parse failed, invalid JSON in config file");
        exit(1);
    }

    log_message("config loaded from %s", CONFIG_FILE_PATH);
}

/**
 * 从配置读取字符串
 */
static char* config_get_string(const char *name) {
    if (!g_config_root) config_init();

    cJSON *item = cJSON_GetObjectItem(g_config_root, name);
    if (!item || !item->valuestring) {
        log_message("config_get_string: '%s' not found", name);
        return NULL;
    }
    return strdup(item->valuestring);
}

/**
 * 从配置读取整数
 */
static int config_get_int(const char *name) {
    char *val = config_get_string(name);
    if (!val) return 0;
    int result = atoi(val);
    free(val);
    return result;
}

/**
 * 从配置读取数组 [qos, interval]
 * @param name JSON key 名称
 * @param qos 输出 QoS 值
 * @param interval 输出间隔秒数
 * @param enabled 输出是否启用
 */
static void config_get_msg_array(const char *name, int *qos, int *interval, int *enabled) {
    if (!g_config_root) config_init();

    if (qos) *qos = 0;
    if (interval) *interval = 0;
    if (enabled) *enabled = 0;

    cJSON *item = cJSON_GetObjectItem(g_config_root, name);
    if (!item || item->type != cJSON_Array) {
        log_message("config_get_msg_array: '%s' not found or not array", name);
        return;
    }

    cJSON *arr0 = cJSON_GetArrayItem(item, 0);
    cJSON *arr1 = cJSON_GetArrayItem(item, 1);

    if (qos) *qos = arr0 ? arr0->valueint : 0;
    if (interval) *interval = arr1 ? arr1->valueint : 0;
    if (enabled) {
        *enabled = (arr0 && arr1 && arr0->valueint > 0 && arr1->valueint > 0) ? 1 : 0;
    }

    log_message("config_get_msg_array: %s -> [qos=%d, interval=%d, enabled=%d]",
                name, qos ? *qos : -1, interval ? *interval : -1, enabled ? *enabled : -1);
}

/* ==================== 公共 API ==================== */

/**
 * 加载完整配置到 Context 结构体
 * 失败直接退出程序
 */
Context* mqtt_config_load(const char *path) {
    (void)path;  /* 使用 CONFIG_FILE_PATH */

    config_init();  /* 确保配置已加载 */

    Context *ctx = calloc(1, sizeof(Context));
    if (!ctx) {
        log_message("FATAL: calloc failed");
        exit(1);
    }

    char *tmp = NULL;

    tmp = config_get_string("address");
    if (tmp) { strncpy(ctx->address, tmp, MAX_ADDRESS_LEN - 1); free(tmp); }

    tmp = config_get_string("auth_sub_topic");
    if (tmp) { strncpy(ctx->sub_topic, tmp, MAX_TOPIC_LEN - 1); free(tmp); }

    tmp = config_get_string("auth_sub_clientid");
    if (tmp) { strncpy(ctx->sub_clientid, tmp, MAX_CLIENTID_LEN - 1); free(tmp); }

    tmp = config_get_string("auth_pub_topic");
    if (tmp) { strncpy(ctx->pub_topic, tmp, MAX_TOPIC_LEN - 1); free(tmp); }

    tmp = config_get_string("auth_pub_clientid");
    if (tmp) { strncpy(ctx->pub_clientid, tmp, MAX_CLIENTID_LEN - 1); free(tmp); }

    tmp = config_get_string("dev_uuid");
    if (tmp) { strncpy(ctx->dev_uuid, tmp, MAX_TOPIC_LEN - 1); free(tmp); }
    /* 如果配置文件没有 dev_uuid，从系统读取真实 UUID */
    if (ctx->dev_uuid[0] == '\0') {
        FILE *fp = fopen("/sys/class/dmi/id/product_uuid", "r");
        if (fp) {
            char sys_uuid[64] = {0};
            if (fgets(sys_uuid, sizeof(sys_uuid), fp)) {
                size_t len = strlen(sys_uuid);
                while (len > 0 && (sys_uuid[len-1] == '\n' || sys_uuid[len-1] == '\r'))
                    sys_uuid[--len] = '\0';
                if (len > 0) {
                    strncpy(ctx->dev_uuid, sys_uuid, MAX_TOPIC_LEN - 1);
                    ctx->dev_uuid[MAX_TOPIC_LEN - 1] = '\0';
                    log_message("mqtt_config_load: dev_uuid from sysfs: %s", ctx->dev_uuid);
                }
            }
            fclose(fp);
        }
        if (ctx->dev_uuid[0] == '\0') {
            strncpy(ctx->dev_uuid, "unknown", MAX_TOPIC_LEN - 1);
        }
    }

    tmp = config_get_string("cloud_sub_clientid");
    if (tmp) { strncpy(ctx->cloud_sub_clientid, tmp, MAX_CLIENTID_LEN - 1); free(tmp); }

    tmp = config_get_string("cloud_sub_topic");
    if (tmp) { strncpy(ctx->cloud_sub_topic, tmp, MAX_TOPIC_LEN - 1); free(tmp); }

    tmp = config_get_string("cloud_pub_clientid");
    if (tmp) { strncpy(ctx->cloud_pub_clientid, tmp, MAX_CLIENTID_LEN - 1); free(tmp); }

    tmp = config_get_string("cloud_pub_topic");
    if (tmp) { strncpy(ctx->cloud_pub_topic, tmp, MAX_TOPIC_LEN - 1); free(tmp); }

    ctx->auth_qos = config_get_int("auth_qos");

    /* 各消息类型配置 [qos, interval] */
    /* device_msg: [qos, interval] - interval 存入 send_interval */
    int tmp_interval = 0;
    config_get_msg_array("device_msg", &ctx->device_qos, &tmp_interval, NULL);
    if (tmp_interval > 0) ctx->send_interval = tmp_interval;

    /* network_msg, log_msg: 只读取 qos，间隔在运行时硬编码 */
    config_get_msg_array("network_msg", &ctx->network_qos, NULL, NULL);
    config_get_msg_array("log_msg", &ctx->log_qos, NULL, NULL);

    /* TLS / 认证配置 */
    tmp = config_get_string("ca_cert");
    if (tmp) { strncpy(ctx->ca_cert, tmp, sizeof(ctx->ca_cert) - 1); free(tmp); }
    tmp = config_get_string("client_cert");
    if (tmp) { strncpy(ctx->client_cert, tmp, sizeof(ctx->client_cert) - 1); free(tmp); }
    tmp = config_get_string("client_key");
    if (tmp) { strncpy(ctx->client_key, tmp, sizeof(ctx->client_key) - 1); free(tmp); }
    tmp = config_get_string("username");
    if (tmp) { strncpy(ctx->username, tmp, sizeof(ctx->username) - 1); free(tmp); }
    tmp = config_get_string("password");
    if (tmp) { strncpy(ctx->password, tmp, sizeof(ctx->password) - 1); free(tmp); }
    ctx->use_cert_auth = config_get_int("use_cert_auth");
    ctx->tls_version = config_get_int("tls_version");
    if (ctx->tls_version < 0) ctx->tls_version = 0; /* 0=自动协商 */

    /* 兼容旧配置: send_interval 作为总默认间隔 */
    if (ctx->send_interval <= 0) ctx->send_interval = 10;

    log_message("mqtt_config_load: OK, address=%s, auth_qos=%d, device_qos=%d, net_qos=%d, log_qos=%d, interval=%d",
               ctx->address, ctx->auth_qos, ctx->device_qos,
               ctx->network_qos, ctx->log_qos, ctx->send_interval);
    return ctx;
}

/**
 * 释放 Context 内存
 */
void mqtt_config_free(Context *ctx) {
    if (g_config_root) {
        cJSON_Delete(g_config_root);
        g_config_root = NULL;
    }
    if (ctx) free(ctx);
}

/**
 * 读取配置项字符串（供外部调用）
 */
char* mqtt_config_read_string(const char *name) {
    return config_get_string(name);
}

/**
 * 读取配置项整数（供外部调用）
 */
int mqtt_config_read_int(const char *name) {
    return config_get_int(name);
}

/* ==================== Unix Socket 命令接口实现 ==================== */
/**
 * 创建 Unix Domain Socket 命令接口
 */
int mqtt_cmd_server_create(const char *socket_path) {
    unlink(socket_path);

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    chmod(socket_path, 0666);

    if (listen(sock, 5) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

/**
 * 关闭并删除 Unix Domain Socket
 */
void mqtt_cmd_server_close(const char *socket_path) {
    unlink(socket_path);
}

/**
 * 处理单个命令
 */
void mqtt_cmd_handle(MqttCmd *cmd, MqttCmdResp *resp) {
    memset(resp, 0, sizeof(*resp));

    log_message("mqtt_cmd_handle: cmd_type=%d, data=%s", cmd->cmd_type, cmd->data);

    switch (cmd->cmd_type) {
        case CMD_DEVICE_AUTH:
            resp->code = 0;
            strcpy(resp->message, "Device auth command received");
            snprintf(resp->data, sizeof(resp->data), "%s", cmd->data);
            /* 通过管道发送命令给client进程 */
            if (g_client_cmd_fd >= 0) {
                write(g_client_cmd_fd, cmd, sizeof(MqttCmd));
                log_message("mqtt_cmd_handle: sent CMD_DEVICE_AUTH to client pipe");
            } else {
                log_message("mqtt_cmd_handle: client pipe not available");
            }
            break;

        case CMD_DEVICE_TEST:
            log_message("========================================");
            log_message("[TEST-DAEMON] 收到连通性测试命令");
            log_message("[TEST-DAEMON] 命令数据: %s", cmd->data);
            resp->code = 0;
            strcpy(resp->message, "Test command forwarded");
            /* 转发命令给 client，结果由 client 写入文件后由 plugin 轮询 */
            if (g_client_cmd_fd >= 0) {
                write(g_client_cmd_fd, cmd, sizeof(MqttCmd));
                log_message("[TEST-DAEMON] 命令已转发到 client pipe (fd=%d)", g_client_cmd_fd);
                log_message("[TEST-DAEMON] 等待 client 完成 MQTT 通路测试...");
            } else {
                resp->code = -1;
                strcpy(resp->message, "Client pipe not available");
                log_message("[TEST-DAEMON] ✗ client pipe 不可用");
            }
            log_message("========================================");
            break;

        case CMD_DEVICE_STOP:
            {
                resp->code = 0;
                strcpy(resp->message, "Device stop command received");
                /* 通过管道发送停止命令给client进程 */
                if (g_client_cmd_fd >= 0) {
                    write(g_client_cmd_fd, cmd, sizeof(MqttCmd));
                    log_message("mqtt_cmd_handle: sent CMD_DEVICE_STOP to client pipe");
                } else {
                    log_message("mqtt_cmd_handle: client pipe not available for stop");
                }

                /* 同时直接从云端设备列表中删除该设备（确保删除成功） */
                cJSON *stop_req = cJSON_Parse(cmd->data);
                if (stop_req) {
                    cJSON *uuid = cJSON_GetObjectItem(stop_req, "dev_uuid");
                    if (uuid && uuid->valuestring) {
                        /* 删除设备数据文件 */
                        char data_file[320];
                        snprintf(data_file, sizeof(data_file),
                                 "/tmp/cloud_device_%s.json", uuid->valuestring);
                        unlink(data_file);

                        /* 从设备列表JSON中移除 */
                        FILE *fp = fopen("/tmp/cloud_devices.json", "r");
                        if (fp) {
                            fseek(fp, 0, SEEK_END);
                            long fsize = ftell(fp);
                            fseek(fp, 0, SEEK_SET);
                            if (fsize > 0) {
                                char *content = malloc(fsize + 1);
                                if (content) {
                                    fread(content, 1, fsize, fp);
                                    content[fsize] = '\0';
                                    fclose(fp);
                                    fp = NULL;

                                    cJSON *root = cJSON_Parse(content);
                                    free(content);
                                    if (root) {
                                        cJSON *devices = cJSON_GetObjectItem(root, "devices");
                                        if (devices && cJSON_IsArray(devices)) {
                                            int idx = 0;
                                            cJSON *item;
                                            cJSON_ArrayForEach(item, devices) {
                                                cJSON *uid = cJSON_GetObjectItem(item, "dev_uuid");
                                                if (uid && uid->valuestring &&
                                                    strcmp(uid->valuestring, uuid->valuestring) == 0) {
                                                    cJSON_DeleteItemFromArray(devices, idx);
                                                    break;
                                                }
                                                idx++;
                                            }
                                        }
                                        fp = fopen("/tmp/cloud_devices.json", "w");
                                        if (fp) {
                                            char *str = cJSON_Print(root);
                                            if (str) { fprintf(fp, "%s", str); free(str); }
                                            fclose(fp);
                                            fp = NULL;
                                        }
                                        cJSON_Delete(root);
                                        log_message("mqtt_cmd_handle: removed device %s from cloud list",
                                                   uuid->valuestring);
                                    }
                                }
                            }
                            if (fp) fclose(fp);
                        }
                    }
                    cJSON_Delete(stop_req);
                }
            }
            break;

        case CMD_CLOUD_CONNECT:
            resp->code = 0;
            strcpy(resp->message, "Cloud connect command received");
            snprintf(resp->data, sizeof(resp->data), "%s", cmd->data);
            break;

        case CMD_CLOUD_DISCONNECT:
            resp->code = 0;
            strcpy(resp->message, "Cloud disconnect command received");
            break;

        case CMD_GET_DEVICES:
            {
                resp->code = 0;
                strcpy(resp->message, "success");
                /* 从cloud设备文件读取真实设备列表 */
                FILE *dev_fp = fopen("/tmp/cloud_devices.json", "r");
                if (dev_fp) {
                    fseek(dev_fp, 0, SEEK_END);
                    long fsize = ftell(dev_fp);
                    fseek(dev_fp, 0, SEEK_SET);
                    if (fsize > 0 && fsize < (long)sizeof(resp->data) - 1) {
                        fread(resp->data, 1, fsize, dev_fp);
                        resp->data[fsize] = '\0';
                    } else {
                        strcpy(resp->data, "{\"devices\":[]}");
                    }
                    fclose(dev_fp);
                } else {
                    strcpy(resp->data, "{\"devices\":[]}");
                }
            }
            break;

        case CMD_GET_DEVICE_DETAIL:
            {
                resp->code = 0;
                strcpy(resp->message, "success");

                /* 解析请求中的 dev_uuid */
                cJSON *req = cJSON_Parse(cmd->data);
                if (req) {
                    cJSON *uuid = cJSON_GetObjectItem(req, "dev_uuid");
                    if (uuid && uuid->valuestring) {
                        /* 读取该设备的存储数据 */
                        char data_file[320];
                        snprintf(data_file, sizeof(data_file),
                                 "/tmp/cloud_device_%s.json", uuid->valuestring);
                        FILE *fp = fopen(data_file, "r");
                        if (fp) {
                            fseek(fp, 0, SEEK_END);
                            long fsize = ftell(fp);
                            fseek(fp, 0, SEEK_SET);
                            if (fsize > 0 && fsize < (long)sizeof(resp->data) - 1) {
                                fread(resp->data, 1, fsize, fp);
                                resp->data[fsize] = '\0';
                            }
                            fclose(fp);
                        }
                        if (!resp->data[0]) {
                            strcpy(resp->data, "{\"device\":null,\"network\":null,\"log\":null}");
                        }
                    }
                    cJSON_Delete(req);
                }
            }
            break;

        default:
            resp->code = -1;
            strcpy(resp->message, "Unknown command");
            break;
    }
}

/**
 * 命令服务器主循环
 */
void mqtt_cmd_server_loop(int cmd_sock) {
    fd_set read_fds;
    struct timeval tv;

    log_message("mqtt_cmd_server_loop: started, listening on socket %d", cmd_sock);

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(cmd_sock, &read_fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int sel = select(cmd_sock + 1, &read_fds, NULL, NULL, &tv);
        if (sel < 0) break;

        if (sel > 0 && FD_ISSET(cmd_sock, &read_fds)) {
            int client_sock = accept(cmd_sock, NULL, NULL);
            if (client_sock >= 0) {
                MqttCmd cmd;
                memset(&cmd, 0, sizeof(cmd));

                /* 循环读取，处理流式套接字的短读 */
                size_t total_read = 0;
                while (total_read < sizeof(cmd)) {
                    int n = recv(client_sock, (char*)&cmd + total_read, sizeof(cmd) - total_read, 0);
                    if (n <= 0) break;
                    total_read += n;
                }
                if (total_read == sizeof(cmd)) {
                    MqttCmdResp resp;
                    mqtt_cmd_handle(&cmd, &resp);

                    /* 循环发送，处理短写 */
                    size_t total_sent = 0;
                    while (total_sent < sizeof(resp)) {
                        int n = send(client_sock, (char*)&resp + total_sent, sizeof(resp) - total_sent, 0);
                        if (n <= 0) break;
                        total_sent += n;
                    }
                }
                close(client_sock);
            }
        }
    }

    log_message("mqtt_cmd_server_loop: exited");
}

/* ==================== 工具函数实现 ==================== */
/**
 * 生成随机字符串
 */
void mqtt_generate_random_string(char *str, int len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz";
    int charset_size = sizeof(charset) - 1;

    srand(time(NULL));

    for (int i = 0; i < len; i++) {
        int index = rand() % charset_size;
        str[i] = charset[index];
    }
    str[len] = '\0';
}

/* ==================== 兼容旧代码 ==================== */
/**
 * 兼容旧代码
 */
char* Read_File_Content(const char *name) {
    return config_get_string(name);
}

/**
 * 兼容旧代码
 */
void generate_random_string(char *str) {
    mqtt_generate_random_string(str, 20);
}

/* ==================== 配置保存函数 ==================== */
/**
 * 保存 auth_channel 到配置文件
 */
int save_auth_channel(const char *auth_channel) {
    if (!g_config_root) config_init();

    /* 更新或添加 auth_channel 字段 */
    cJSON_DeleteItemFromObject(g_config_root, "auth_channel");
    cJSON_AddStringToObject(g_config_root, "auth_channel", auth_channel);

    /* 写回文件 */
    FILE *fp = fopen(CONFIG_FILE_PATH, "w");
    if (!fp) {
        log_message("save_auth_channel: cannot open config file for write");
        return -1;
    }

    char *str = cJSON_Print(g_config_root);
    if (str) {
        fprintf(fp, "%s", str);
        free(str);
    }
    fclose(fp);

    log_message("save_auth_channel: saved %s", auth_channel);
    return 0;
}

/**
 * 保存设备列表到文件
 */
int save_devices_list(const char *devices_json) {
    const char *devices_file = "/tmp/mqtt_devices.json";

    FILE *fp = fopen(devices_file, "w");
    if (!fp) {
        log_message("save_devices_list: cannot open file");
        return -1;
    }
    fprintf(fp, "%s", devices_json);
    fclose(fp);

    log_message("save_devices_list: saved to %s", devices_file);
    return 0;
}
