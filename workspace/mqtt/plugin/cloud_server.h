#ifndef CLOUD_SERVER_H
#define CLOUD_SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <MQTTAsync.h>
#include "cjson/cJSON.h"

#define CLOUD_SUB_TOPIC "client/dev/+/auth"
#define CLOUD_DATA_SUB_TOPIC "client/dev/+/+/+"
#define CLOUD_PUB_TOPIC "cloud/auth"

#define MAX_DEVICES 256

typedef struct {
    char dev_uuid[64];
    char auth_channel[256];
    char data_types[32];  // "device,network,log"
    time_t auth_time;
    time_t last_update;
    int online;
    cJSON *device_data;
    cJSON *network_data;
    cJSON *log_data;
} DeviceRecord;

typedef struct {
    char address[128];
    int qos;
    char sub_clientid[64];
    char sub_topic[128];
    char pub_clientid[64];
    char pub_topic[128];
    int running;
    DeviceRecord devices[MAX_DEVICES];
    int device_count;
    pthread_mutex_t mutex;
    pthread_t dispatch_thread;
} CloudServer;

int cloud_server_init(CloudServer *cs, const char *address);
int cloud_server_start(CloudServer *cs);
int cloud_server_stop(CloudServer *cs);
void cloud_server_destroy(CloudServer *cs);

int cloud_get_devices(CloudServer *cs, DeviceRecord **out_devices, int *out_count);

#endif
