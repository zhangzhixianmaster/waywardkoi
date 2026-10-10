#ifndef DEVICE_CLIENT_H
#define DEVICE_CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/utsname.h>
#include <MQTTAsync.h>
#include "cjson/cJSON.h"

#define CLIENT_SUB_TOPIC "cloud/#"
#define CLIENT_PUB_TOPIC "client/dev/%s/auth"
#define CLIENT_DATA_TOPIC "client/dev/%s/data"
#define AUTH_REPLY_TOPIC "cloud/auth"

#define QOS 2

typedef struct {
    char address[128];
    char dev_uuid[64];
    int data_types;  // bit flags: 1=device, 2=network, 4=log
    char auth_channel[256];  // 授权后获得的通道
    int auth_status;  // 0=idle, 1=sent, 2=authorized
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} DeviceClient;

int device_client_init(DeviceClient *dc, const char *address, const char *dev_uuid, int data_types);
int device_client_send_auth(DeviceClient *dc);
int device_client_start_send(DeviceClient *dc);
void device_client_stop(DeviceClient *dc);
void device_client_destroy(DeviceClient *dc);

#endif
