#ifndef MQTT_CMD_H
#define MQTT_CMD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define MQTT_CMD_SOCKET "/tmp/mqtt_daemon.sock"
#define MQTT_CMD_MAX_LEN 1024

// Command types
#define CMD_DEVICE_AUTH      1
#define CMD_DEVICE_STOP      2
#define CMD_CLOUD_CONNECT    3
#define CMD_CLOUD_DISCONNECT 4
#define CMD_GET_DEVICES      5
#define CMD_GET_DEVICE_DETAIL 6
#define CMD_DEVICE_TEST      7  /* 连通性测试：client→cloud 验证连接并返回结果 */

typedef struct {
    int cmd_type;
    char data[MQTT_CMD_MAX_LEN];  // JSON data
} MqttCmd;

typedef struct {
    int code;
    char message[256];
    char data[MQTT_CMD_MAX_LEN];  // JSON response
} MqttCmdResp;

// Helper: send command and get response
int mqtt_cmd_send(int cmd_type, const char *json_data, MqttCmdResp *resp);

// Server functions (implemented in mqtt_lib.c)
int mqtt_cmd_server_create(const char *socket_path);
void mqtt_cmd_server_close(const char *socket_path);
void mqtt_cmd_server_loop(int cmd_sock);
void mqtt_cmd_handle(MqttCmd *cmd, MqttCmdResp *resp);

#endif