/*
 * mqtt_plugin.c - MQTT 插件，供 configd 调用
 *
 * 注意：本插件只是命令中转站，不创建 MQTT 连接
 * 所有 MQTT 操作由 mqtt daemon (client程序) 处理
 *
 * 导出的 action 函数:
 *   device_auth        - 设备端发送认证请求
 *   cloud_connect     - 服务端连接 MQTT
 *   cloud_disconnect  - 服务端断开连接
 *   get_auth_devices  - 获取已授权设备列表
 *   get_device_detail - 获取设备详细信息
 *   get_config        - 获取配置文件
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include "../common/mqtt_cmd.h"

/* 日志 - 写到 /var/log/work_log/mqtt_plugin.log */
#define LOG_FILE_PATH "/var/log/work_log/mqtt_plugin.log"

static void log_write(const char *fmt, ...) {
    FILE *fp = fopen(LOG_FILE_PATH, "a");
    if (fp) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
        va_list args;
        va_start(args, fmt);
        fprintf(fp, "[%s] [plugin] ", timestamp);
        vfprintf(fp, fmt, args);
        fprintf(fp, "\n");
        fflush(fp);
        fclose(fp);
        va_end(args);
    }
}

/* DLLMain - 插件加载时自动调用 */
__attribute__((constructor))
static void on_plugin_load(void) {
    log_write("=== MQTT Plugin loaded (command relay mode) ===");
}

/* 辅助函数：创建标准响应 JSON */
static char* create_response(int code, const char *message, cJSON *data) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "code", code);
    cJSON_AddStringToObject(obj, "message", message);
    if (data) {
        cJSON_AddItemToObject(obj, "data", data);
    } else {
        cJSON_AddNullToObject(obj, "data");
    }
    char *str = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    return str;
}

/* 通过 socket 发送命令给 mqtt daemon */
static int send_cmd_to_daemon(int cmd_type, const char *json_data, MqttCmdResp *resp) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        log_write("socket() failed");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, MQTT_CMD_SOCKET, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_write("connect() to %s failed - daemon not running?", MQTT_CMD_SOCKET);
        close(sock);
        return -1;
    }

    MqttCmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd_type = cmd_type;
    if (json_data) {
        strncpy(cmd.data, json_data, sizeof(cmd.data) - 1);
    }

    log_write("Sending cmd=%d, data=%s", cmd_type, json_data ? json_data : "");

    if (send(sock, &cmd, sizeof(cmd), 0) < 0) {
        log_write("send() failed");
        close(sock);
        return -1;
    }

    memset(resp, 0, sizeof(*resp));
    if (recv(sock, resp, sizeof(*resp), 0) < 0) {
        log_write("recv() failed");
        close(sock);
        return -1;
    }

    close(sock);
    log_write("Response: code=%d, msg=%s", resp->code, resp->message);
    return 0;
}

/* ==================== 设备端接口 ==================== */

char* device_auth(const char *data_json, int *out_status) {
    log_write("device_auth called with: %s", data_json);

    MqttCmdResp resp;
    if (send_cmd_to_daemon(CMD_DEVICE_AUTH, data_json, &resp) < 0) {
        *out_status = 503;
        return create_response(-1, "MQTT daemon not running", NULL);
    }

    *out_status = (resp.code == 0) ? 200 : 400;
    cJSON *data = NULL;
    if (resp.data[0]) {
        data = cJSON_Parse(resp.data);
    }
    return create_response(resp.code, resp.message, data);
}

/* ==================== 服务端接口 ==================== */

char* cloud_connect(const char *data_json, int *out_status) {
    log_write("cloud_connect called with: %s", data_json);

    MqttCmdResp resp;
    if (send_cmd_to_daemon(CMD_CLOUD_CONNECT, data_json, &resp) < 0) {
        *out_status = 503;
        return create_response(-1, "MQTT daemon not running", NULL);
    }

    *out_status = (resp.code == 0) ? 200 : 400;
    cJSON *data = NULL;
    if (resp.data[0]) {
        data = cJSON_Parse(resp.data);
    }
    return create_response(resp.code, resp.message, data);
}

char* cloud_disconnect(const char *data_json, int *out_status) {
    log_write("cloud_disconnect called");

    MqttCmdResp resp;
    if (send_cmd_to_daemon(CMD_CLOUD_DISCONNECT, data_json, &resp) < 0) {
        *out_status = 503;
        return create_response(-1, "MQTT daemon not running", NULL);
    }

    *out_status = (resp.code == 0) ? 200 : 400;
    return create_response(resp.code, resp.message, NULL);
}

char* device_stop(const char *data_json, int *out_status) {
    log_write("device_stop called");

    MqttCmdResp resp;
    if (send_cmd_to_daemon(CMD_DEVICE_STOP, data_json, &resp) < 0) {
        *out_status = 503;
        return create_response(-1, "MQTT daemon not running", NULL);
    }

    *out_status = (resp.code == 0) ? 200 : 400;
    return create_response(resp.code, resp.message, NULL);
}

char* get_auth_devices(const char *data_json, int *out_status) {
    log_write("get_auth_devices called");

    MqttCmdResp resp;
    if (send_cmd_to_daemon(CMD_GET_DEVICES, data_json, &resp) < 0) {
        *out_status = 503;
        return create_response(-1, "MQTT daemon not running", NULL);
    }

    *out_status = (resp.code == 0) ? 200 : 400;
    cJSON *data = NULL;
    if (resp.data[0]) {
        data = cJSON_Parse(resp.data);
    }
    return create_response(resp.code, resp.message, data);
}

char* get_device_detail(const char *data_json, int *out_status) {
    log_write("get_device_detail called with: %s", data_json);

    MqttCmdResp resp;
    if (send_cmd_to_daemon(CMD_GET_DEVICE_DETAIL, data_json, &resp) < 0) {
        *out_status = 503;
        return create_response(-1, "MQTT daemon not running", NULL);
    }

    *out_status = (resp.code == 0) ? 200 : 400;
    cJSON *data = NULL;
    if (resp.data[0]) {
        data = cJSON_Parse(resp.data);
    }
    return create_response(resp.code, resp.message, data);
}
/* ==================== 获取配置 ==================== */
char* get_config(const char *data_json, int *out_status) {
    (void)data_json;
    log_write("get_config called");

    FILE *fp = fopen("/home/workspace/mqtt/file/config.json", "r");
    if (!fp) {
        *out_status = 500;
        return create_response(-1, "Cannot open config file", NULL);
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *content = malloc(fsize + 1);
    if (!content) {
        fclose(fp);
        *out_status = 500;
        return create_response(-1, "Memory error", NULL);
    }

    fread(content, 1, fsize, fp);
    content[fsize] = '\0';
    fclose(fp);

    cJSON *config = cJSON_Parse(content);
    free(content);

    if (!config) {
        *out_status = 500;
        return create_response(-1, "Invalid JSON in config", NULL);
    }

    *out_status = 200;
    return create_response(0, "success", config);
}

/* ==================== 配置保存/读取 ==================== */

static const char *WORK_DIR = "/data/work";
static const char *ADDR_FILE = "/data/work/mqtt_addr.b64";
static const char *CLIENT_STATE_FILE = "/data/work/client_state.b64";
static const char *CLOUD_DEVICES_FILE = "/data/work/cloud_devices.b64";

static int ensure_work_dir(void) {
    if (mkdir(WORK_DIR, 0755) != 0 && errno != EEXIST) {
        log_write("ensure_work_dir: mkdir failed");
        return -1;
    }
    return 0;
}

/* 简单base64编码 */
static char* base64_encode(const char *input, int len) {
    static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *output = malloc((len + 2) * 4 / 3 + 1);
    int i, j = 0;
    
    for (i = 0; i < len; i += 3) {
        int a = input[i];
        int b = (i + 1 < len) ? input[i + 1] : 0;
        int c = (i + 2 < len) ? input[i + 2] : 0;
        
        output[j++] = b64_table[a >> 2];
        output[j++] = b64_table[((a & 3) << 4) | (b >> 4)];
        output[j++] = (i + 1 < len) ? b64_table[((b & 15) << 2) | (c >> 6)] : '=';
        output[j++] = (i + 2 < len) ? b64_table[c & 63] : '=';
    }
    output[j] = '\0';
    return output;
}

/* 简单base64解码 */
static char* base64_decode(const char *input, int *out_len) {
    static unsigned char dec_table[256] = {0};
    static int init = 0;

    if (!init) {
        const char *b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; b64chars[i]; i++) dec_table[(unsigned char)b64chars[i]] = i;
        init = 1;
    }

    int len = strlen(input);
    while (len > 0 && input[len - 1] == '=') len--;

    char *output = malloc(len * 3 / 4 + 1);
    int i, j = 0;

    for (i = 0; i < len; i += 4) {
        int a = dec_table[(unsigned char)input[i]];
        int b = (i + 1 < len) ? dec_table[(unsigned char)input[i + 1]] : 0;
        int c = (i + 2 < len) ? dec_table[(unsigned char)input[i + 2]] : 0;
        int d = (i + 3 < len) ? dec_table[(unsigned char)input[i + 3]] : 0;

        output[j++] = (a << 2) | (b >> 4);
        if (input[i + 2] != '=') output[j++] = ((b & 15) << 4) | (c >> 2);
        if (input[i + 3] != '=') output[j++] = ((c & 3) << 6) | d;
    }
    output[j] = '\0';
    if (out_len) *out_len = j;
    return output;
}

/* 保存地址 */
char* save_mqtt_address(const char *data_json, int *out_status) {
    log_write("save_mqtt_address called");
    
    cJSON *data = cJSON_Parse(data_json);
    if (!data) {
        *out_status = 400;
        return create_response(-1, "Invalid JSON", NULL);
    }
    
    cJSON *address = cJSON_GetObjectItem(data, "address");
    if (!address || !address->valuestring) {
        cJSON_Delete(data);
        *out_status = 400;
        return create_response(-1, "Missing address", NULL);
    }
    
    ensure_work_dir();
    
    /* base64编码保存 */
    char *encoded = base64_encode(address->valuestring, strlen(address->valuestring));
    FILE *fp = fopen(ADDR_FILE, "w");
    if (!fp) {
        free(encoded);
        cJSON_Delete(data);
        *out_status = 500;
        return create_response(-1, "Cannot write file", NULL);
    }
    fprintf(fp, "%s", encoded);
    fclose(fp);
    free(encoded);
    cJSON_Delete(data);
    
    log_write("save_mqtt_address: saved %s", address->valuestring);
    *out_status = 200;
    return create_response(0, "success", NULL);
}

/* 读取地址 */
char* get_mqtt_address(const char *data_json, int *out_status) {
    (void)data_json;
    log_write("get_mqtt_address called");
    
    /* 优先读保存的 */
    FILE *fp = fopen(ADDR_FILE, "r");
    if (fp) {
        char buf[512] = {0};
        fgets(buf, sizeof(buf), fp);
        fclose(fp);
        
        int decoded_len = 0;
        char *decoded = base64_decode(buf, &decoded_len);
        if (decoded) {
            decoded[decoded_len] = '\0';
            cJSON *result = cJSON_CreateObject();
            cJSON_AddStringToObject(result, "address", decoded);
            cJSON_AddNumberToObject(result, "source", 1); /* 1=保存的 */
            free(decoded);
            *out_status = 200;
            return create_response(0, "success", result);
        }
    }
    
    /* 读config.json */
    fp = fopen("/home/workspace/mqtt/file/config.json", "r");
    if (!fp) {
        *out_status = 404;
        return create_response(-1, "No config found", NULL);
    }
    
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *content = malloc(fsize + 1);
    fread(content, 1, fsize, fp);
    content[fsize] = '\0';
    fclose(fp);
    
    cJSON *config = cJSON_Parse(content);
    free(content);
    
    if (!config) {
        *out_status = 500;
        return create_response(-1, "Invalid config", NULL);
    }
    
    cJSON *addr = cJSON_GetObjectItem(config, "address");
    if (!addr || !addr->valuestring) {
        cJSON_Delete(config);
        *out_status = 404;
        return create_response(-1, "No address", NULL);
    }
    
    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "address", addr->valuestring);
    cJSON_AddNumberToObject(result, "source", 0); /* 0=config.json */
    cJSON_Delete(config);
    
    *out_status = 200;
    return create_response(0, "success", result);
}

/* ==================== 获取机器UUID ==================== */
char* get_uuid(const char *data_json, int *out_status) {
    (void)data_json;
    log_write("get_uuid called");

    FILE *fp = fopen("/sys/class/dmi/id/product_uuid", "r");
    if (!fp) {
        *out_status = 500;
        return create_response(-1, "Cannot open product_uuid", NULL);
    }

    char uuid[64] = {0};
    if (fgets(uuid, sizeof(uuid), fp) == NULL) {
        fclose(fp);
        *out_status = 500;
        return create_response(-1, "Cannot read uuid", NULL);
    }
    fclose(fp);

    // 去掉换行符
    int len = strlen(uuid);
    while (len > 0 && (uuid[len-1] == '\n' || uuid[len-1] == '\r')) {
        uuid[--len] = '\0';
    }

    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "uuid", uuid);

    *out_status = 200;
    return create_response(0, "success", result);
}

/* ==================== 连通性测试 (完整 MQTT 通路测试) ==================== */
/*
 * device_test: 端到端连通性测试
 * 流程: configd → mqtt_daemon → client进程 → MQTT发布(client/auth,test:true)
 *       → cloud收到 → 验证 → 发布结果(cloud/{uuid}/test) → client收到
 *       → 结果回传configd → 返回前端
 * 超时: 5 秒无响应返回"连接超时"
 */
char* device_test(const char *data_json, int *out_status) {
    log_write("device_test called");

    cJSON *req = cJSON_Parse(data_json);
    if (!req) {
        *out_status = 400;
        return create_response(-1, "Invalid JSON", NULL);
    }

    /* 构建发送给 daemon 的 JSON */
    cJSON *test_data = cJSON_CreateObject();
    cJSON *addr_obj = cJSON_GetObjectItem(req, "address");
    cJSON *uuid_obj = cJSON_GetObjectItem(req, "dev_uuid");

    if (addr_obj && cJSON_IsString(addr_obj))
        cJSON_AddStringToObject(test_data, "address", addr_obj->valuestring);
    if (uuid_obj && cJSON_IsString(uuid_obj))
        cJSON_AddStringToObject(test_data, "dev_uuid", uuid_obj->valuestring);

    cJSON_AddBoolToObject(test_data, "test", 1);
    char *json_str = cJSON_PrintUnformatted(test_data);
    cJSON_Delete(test_data);
    cJSON_Delete(req);

    if (!json_str) {
        *out_status = 500;
        return create_response(-1, "Internal error", NULL);
    }

    /* 通过 Unix Socket 发送 CMD_DEVICE_TEST，5 秒超时 */
    log_write("========================================");
    log_write("[TEST-PLUGIN] 连通性测试开始");
    log_write("[TEST-PLUGIN] 请求数据: %s", data_json);
    log_write("[TEST-PLUGIN] 发送命令到 daemon: %s", MQTT_CMD_SOCKET);

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        free(json_str);
        *out_status = 500;
        return create_response(-1, "Cannot create socket", NULL);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, MQTT_CMD_SOCKET, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_write("device_test: daemon not reachable (%s)", strerror(errno));
        close(sock);
        free(json_str);
        cJSON *result = cJSON_CreateObject();
        cJSON_AddNumberToObject(result, "passed", 0);
        cJSON_AddStringToObject(result, "msg", "MQTT 服务未启动");
        *out_status = 200;
        return create_response(0, "success", result);
    }

    /* 设置 5 秒超时 */
    struct timeval tv = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* 发送命令 */
    MqttCmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd_type = CMD_DEVICE_TEST;
    strncpy(cmd.data, json_str, sizeof(cmd.data) - 1);
    free(json_str);

    size_t total_sent = 0;
    while (total_sent < sizeof(cmd)) {
        int n = send(sock, (char*)&cmd + total_sent, sizeof(cmd) - total_sent, 0);
        if (n <= 0) { close(sock); *out_status = 500; return create_response(-1, "Send failed", NULL); }
        total_sent += n;
    }

    /* 等待 daemon 确认收到命令 */
    MqttCmdResp resp;
    memset(&resp, 0, sizeof(resp));
    size_t total_read = 0;
    while (total_read < sizeof(resp)) {
        int n = recv(sock, (char*)&resp + total_read, sizeof(resp) - total_read, 0);
        if (n <= 0) break;
        total_read += n;
    }
    close(sock);

    if (resp.code != 0) {
        log_write("[TEST-PLUGIN] ✗ daemon 返回错误: code=%d msg=%s", resp.code, resp.message);
        cJSON *result = cJSON_CreateObject();
        cJSON_AddNumberToObject(result, "passed", 0);
        cJSON_AddStringToObject(result, "msg", resp.message[0] ? resp.message : "MQTT 服务未启动");
        *out_status = 200;
        return create_response(0, "success", result);
    }

    log_write("[TEST-PLUGIN] daemon 已转发命令，开始轮询结果文件...");

    /* 清除旧结果文件 */
    ensure_work_dir();
    unlink("/data/work/mqtt_test_result.json");

    /* 轮询结果文件，最多等 5 秒 */
    #define TEST_POLL_INTERVAL 200  /* ms */
    #define TEST_POLL_MAX      5000 /* ms */
    int waited = 0;
    cJSON *test_result = NULL;

    while (waited < TEST_POLL_MAX) {
        usleep(TEST_POLL_INTERVAL * 1000);
        waited += TEST_POLL_INTERVAL;

        FILE *fp = fopen("/data/work/mqtt_test_result.json", "r");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            long sz = ftell(fp);
            if (sz > 0) {
                fseek(fp, 0, SEEK_SET);
                char *buf = malloc(sz + 1);
                if (buf) {
                    size_t n = fread(buf, 1, sz, fp);
                    buf[n] = '\0';
                    test_result = cJSON_Parse(buf);
                    free(buf);
                }
            }
            fclose(fp);
            if (test_result) {
                char *dbg = cJSON_PrintUnformatted(test_result);
                log_write("[TEST-PLUGIN] 收到测试结果 (waited=%d ms): %s", waited, dbg);
                free(dbg);
                break;
            }
        }
    }

    if (!test_result) {
        log_write("[TEST-PLUGIN] ✗ 超时: %d ms 内未收到结果", TEST_POLL_MAX);
    }

    cJSON *result = cJSON_CreateObject();
    if (test_result) {
        cJSON *ok  = cJSON_GetObjectItem(test_result, "test_ok");
        cJSON *msg = cJSON_GetObjectItem(test_result, "msg");
        int passed = (ok && cJSON_IsTrue(ok)) ? 1 : 0;
        cJSON_AddNumberToObject(result, "passed", passed);
        cJSON_AddStringToObject(result, "msg",
            (msg && cJSON_IsString(msg)) ? msg->valuestring : (passed ? "连接成功" : "连接失败"));
        log_write("[TEST-PLUGIN] 测试完成: %s", passed ? "✓ 成功" : "✗ 失败");
        cJSON_Delete(test_result);
    } else {
        cJSON_AddNumberToObject(result, "passed", 0);
        cJSON_AddStringToObject(result, "msg", "连接超时（5秒无响应）");
        log_write("[TEST-PLUGIN] 测试完成: ✗ 超时");
    }
    log_write("========================================");

    *out_status = 200;
    return create_response(0, "success", result);
}

/* ==================== 客户端状态保存/读取 ==================== */

char* save_client_state(const char *data_json, int *out_status) {
    log_write("save_client_state called");

    cJSON *data = cJSON_Parse(data_json);
    if (!data) {
        *out_status = 400;
        return create_response(-1, "Invalid JSON", NULL);
    }

    cJSON *address = cJSON_GetObjectItem(data, "address");
    cJSON *data_types = cJSON_GetObjectItem(data, "data_types");
    cJSON *dev_uuid = cJSON_GetObjectItem(data, "dev_uuid");
    cJSON *authorized = cJSON_GetObjectItem(data, "authorized");

    if (!address || !address->valuestring) {
        cJSON_Delete(data);
        *out_status = 400;
        return create_response(-1, "Missing address", NULL);
    }

    ensure_work_dir();

    /* 构建保存内容 */
    cJSON *save_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(save_obj, "address", address->valuestring);
    if (data_types && data_types->valuestring) {
        cJSON_AddStringToObject(save_obj, "data_types", data_types->valuestring);
    }
    if (dev_uuid && dev_uuid->valuestring) {
        cJSON_AddStringToObject(save_obj, "dev_uuid", dev_uuid->valuestring);
    }
    if (authorized) {
        cJSON_AddNumberToObject(save_obj, "authorized", authorized->valueint);
    }

    char *json_str = cJSON_PrintUnformatted(save_obj);
    char *encoded = base64_encode(json_str, strlen(json_str));

    FILE *fp = fopen(CLIENT_STATE_FILE, "w");
    if (!fp) {
        free(encoded);
        free(json_str);
        cJSON_Delete(save_obj);
        cJSON_Delete(data);
        *out_status = 500;
        return create_response(-1, "Cannot write file", NULL);
    }
    fprintf(fp, "%s", encoded);
    fclose(fp);
    free(encoded);
    free(json_str);
    cJSON_Delete(save_obj);
    cJSON_Delete(data);

    log_write("save_client_state: saved");
    *out_status = 200;
    return create_response(0, "success", NULL);
}

char* get_client_state(const char *data_json, int *out_status) {
    (void)data_json;
    log_write("get_client_state called");

    cJSON *state = NULL;

    /* 1. 读取保存的客户端状态 */
    FILE *fp = fopen(CLIENT_STATE_FILE, "r");
    if (fp) {
        char buf[1024] = {0};
        fgets(buf, sizeof(buf), fp);
        fclose(fp);

        int decoded_len = 0;
        char *decoded = base64_decode(buf, &decoded_len);
        if (decoded) {
            decoded[decoded_len] = '\0';
            state = cJSON_Parse(decoded);
            free(decoded);
        }
    }

    /* 2. 读取客户端进程的实时认证状态 */
    int live_auth = 0;
    FILE *status_fp = fopen("/data/work/client_auth_status", "r");
    if (status_fp) {
        fscanf(status_fp, "%d", &live_auth);
        fclose(status_fp);
    }

    /* 3. 合并：实时状态覆盖保存的 authorized */
    if (state && cJSON_IsObject(state)) {
        cJSON_DeleteItemFromObject(state, "authorized");
        cJSON_AddNumberToObject(state, "authorized", live_auth);
    } else if (live_auth == 1) {
        /* 无保存状态但客户端正在运行且已授权 */
        if (state) cJSON_Delete(state);
        state = cJSON_CreateObject();
        cJSON_AddNumberToObject(state, "authorized", 1);
    }

    if (!state) {
        *out_status = 200;
        return create_response(0, "success", NULL);
    }

    *out_status = 200;
    char *resp = create_response(0, "success", state);
    /* 注意: create_response 通过 cJSON_AddItemToObject 接管了 state 的所有权，
       cJSON_Delete(obj) 已递归释放 state，不要在此重复释放 */
    return resp;
}
