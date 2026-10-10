#ifndef MQTT_LIB_H
#define MQTT_LIB_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <cjson/cJSON.h>
#include "MQTTClient.h"
#include "MQTTAsync.h"
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

/* ==================== 日志宏 ==================== */
#define log_message(...) log_message_impl(__FILE__, __LINE__, __VA_ARGS__)

void log_message_impl(const char *file, int line, const char *format, ...);

#define LOG_FILE_PATH "/var/log/work_log/mqtt.log"
#define CONFIG_FILE_PATH "/home/workspace/mqtt/file/config.json"

/* ==================== 常量定义 ==================== */
#define MAX_ADDRESS_LEN 64
#define MAX_TOPIC_LEN 64
#define MAX_CLIENTID_LEN 64
#define MAX_MSG_LEN 256

enum mqtt_type {
    CLOUD_FLAG = 1,
    CLIENT_FLAG
};

/* ==================== 数据结构 ==================== */
typedef struct context_data {
    int flag;
    MQTTAsync client;
    char address[MAX_ADDRESS_LEN];
    char sub_topic[MAX_TOPIC_LEN];
    char sub_clientid[MAX_CLIENTID_LEN];
    char pub_topic[MAX_TOPIC_LEN];
    char pub_clientid[MAX_CLIENTID_LEN];
    char dev_uuid[MAX_TOPIC_LEN];
    char cloud_sub_topic[MAX_TOPIC_LEN];
    char cloud_sub_clientid[MAX_CLIENTID_LEN];
    char cloud_pub_topic[MAX_TOPIC_LEN];
    char cloud_pub_clientid[MAX_CLIENTID_LEN];
    int auth_qos;
    int device_qos;
    int network_qos;
    int log_qos;
    int send_interval;
    int fd;       /* 数据管道，用于mqtt_msg_handle主循环 */
    int cmd_fd;   /* 命令管道，用于接收plugin命令 */
    int running;

    /* TLS / 认证配置 */
    char ca_cert[256];
    char client_cert[256];
    char client_key[256];
    char username[64];
    char password[64];
    int use_cert_auth;   /* 0=用户名密码, 1=证书认证 */
    int tls_version;     /* MQTTAsync_SSL_VERSION_TLS_1_2 = 4 */
} Context;

/* 各消息类型的QoS和发送间隔配置 */
typedef struct {
    int qos;
    int interval;      /* 秒 */
    int enabled;       /* 是否启用 */
    time_t last_send;  /* 上次发送时间 */
} MsgTypeConfig;

typedef struct mqtt_connect_data {
    int fd;
    int type;
    int flag;
    MQTTAsync client;
    MQTTAsync_responseOptions *conn_opts;
    char address[MAX_ADDRESS_LEN];
    char topic[MAX_TOPIC_LEN];
    char clientid[MAX_CLIENTID_LEN];
    char dev_uuid[MAX_TOPIC_LEN];
    char pub_topic[MAX_TOPIC_LEN];
    char pub_clientid[MAX_CLIENTID_LEN];
    int auth_qos;

    /* 各消息类型的独立配置 */
    MsgTypeConfig device_cfg;
    MsgTypeConfig network_cfg;
    MsgTypeConfig log_cfg;

    /* Client mode state */
    int client_auth_received;      /* 0=waiting, 1=received */
    char auth_channel[256];        /* Channel from auth reply (legacy) */
    char dev_channel[256];         /* 设备/系统信息通道 */
    char net_channel[256];         /* 网络信息通道 */
    char log_channel[256];         /* 日志信息通道 */
    int pending_auth_request;     /* 1=需要发送认证请求，由plugin命令触发 */

    /* TLS / 认证配置（重连时需要） */
    char ca_cert[256];
    char client_cert[256];
    char client_key[256];
    char username[64];
    char password[64];
    int use_cert_auth;
    int tls_version;
} Mqtt_data;

typedef struct publish_data {
    MQTTAsync client;
    int qos;
    char address[MAX_ADDRESS_LEN];
    char topic[MAX_TOPIC_LEN];
    char clientid[MAX_CLIENTID_LEN];
    char pub_msg[MAX_MSG_LEN];
} Publish;

/* ==================== 配置文件操作 ==================== */
/**
 * 从配置文件加载 MQTT 配置到 Context 结构体
 * @param path 配置文件路径
 * @return 分配的 Context 指针，失败返回 NULL
 */
Context* mqtt_config_load(const char *path);

/**
 * 释放 Context 内存
 */
void mqtt_config_free(Context *ctx);

/* ==================== Unix Socket 命令接口 ==================== */
/* 注意: mqtt_cmd_server_create/close/loop 在 mqtt_cmd.h 中定义 */

/* ==================== 工具函数 ==================== */
/**
 * 读取配置文件中的字符串值
 * @param name JSON key 名称
 * @return 分配的字符串指针，失败返回 NULL，使用后需 free()
 */
char* mqtt_config_read_string(const char *name);

/**
 * 读取配置文件中的整数值
 * @param name JSON key 名称
 * @return 整数值
 */
int mqtt_config_read_int(const char *name);

/**
 * 生成随机字符串
 * @param str 输出缓冲区
 * @param len 字符串长度
 */
void mqtt_generate_random_string(char *str, int len);

/* ==================== 兼容旧代码 ==================== */
/** @deprecated 使用 mqtt_config_read_string 代替 */
char* Read_File_Content(const char *name);
/** @deprecated 使用 mqtt_generate_random_string 代替 */
void generate_random_string(char *str);

/* ==================== 全局变量 ==================== */
/* 父进程通过此变量向client子进程发送命令 */
extern int g_client_cmd_fd;

/* ==================== 配置保存函数 ==================== */
int save_auth_channel(const char *auth_channel);
int save_devices_list(const char *devices_json);

#endif