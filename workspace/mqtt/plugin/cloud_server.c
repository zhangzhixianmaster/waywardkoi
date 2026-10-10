#include "cloud_server.h"
#include <unistd.h>
#include <stdarg.h>

static MQTTAsync g_client = NULL;
static CloudServer *g_cs = NULL;

/* 前向声明 */
static void save_devices_to_file(CloudServer *cs);

static void log_msg(const char *fmt, ...) {
    FILE *fp = fopen("/var/log/work_log/mqtt_plugin.log", "a");
    if (fp) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
        va_list args;
        va_start(args, fmt);
        fprintf(fp, "[%s] [cloud_server] ", timestamp);
        vfprintf(fp, fmt, args);
        fprintf(fp, "\n");
        fflush(fp);
        fclose(fp);
        va_end(args);
    }
}

static int send_mqtt_message(const char *topic, const char *payload) {
    if (!g_client) return -1;

    MQTTAsync_message msg = MQTTAsync_message_initializer;
    msg.payload = (void *)payload;
    msg.payloadlen = strlen(payload);
    msg.qos = 2;
    msg.retained = 0;

    MQTTAsync deliveryToken;
    int rc = MQTTAsync_sendMessage(g_client, topic, &msg, &deliveryToken);
    if (rc != MQTTASYNC_SUCCESS) {
        log_msg("Failed to send to %s, rc=%d", topic, rc);
        return -1;
    }
    return 0;
}

static void on_connect(void *context, MQTTAsync_successData *response) {
    log_msg("Cloud server connected to MQTT broker");
    MQTTAsync client = (MQTTAsync)context;
    MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;

    // Subscribe to auth topic
    int rc = MQTTAsync_subscribe(client, CLOUD_SUB_TOPIC, 2, &opts);
    if (rc != MQTTASYNC_SUCCESS) {
        log_msg("Failed to subscribe to %s, rc=%d", CLOUD_SUB_TOPIC, rc);
    } else {
        log_msg("Subscribed to %s", CLOUD_SUB_TOPIC);
    }

    // Subscribe to data topic
    rc = MQTTAsync_subscribe(client, CLOUD_DATA_SUB_TOPIC, 2, &opts);
    if (rc != MQTTASYNC_SUCCESS) {
        log_msg("Failed to subscribe to %s, rc=%d", CLOUD_DATA_SUB_TOPIC, rc);
    } else {
        log_msg("Subscribed to %s", CLOUD_DATA_SUB_TOPIC);
    }
}

static void on_connect_failure(void *context, MQTTAsync_failureData *response) {
    log_msg("Cloud connect failed, rc=%d", response ? response->code : -1);
}

static int on_message(void *context, char *topic, int topicLen, MQTTAsync_message *message) {
    if (!context || !message || !message->payload) return 1;

    CloudServer *cs = (CloudServer *)context;
    char *payload = (char *)message->payload;
    int payloadlen = message->payloadlen;

    log_msg("Received on %s: %.*s", topic, payloadlen, payload);

    cJSON *root = cJSON_Parse(payload);
    if (!root) {
        log_msg("Failed to parse JSON");
        return 1;
    }

    // Check if it's an auth request
    cJSON *auth_req = cJSON_GetObjectItem(root, "auth_request");
    cJSON *dev_uuid = cJSON_GetObjectItem(root, "dev_uuid");
    cJSON *data_types = cJSON_GetObjectItem(root, "data_types");

    if (auth_req && auth_req->type == cJSON_True && dev_uuid && dev_uuid->type == cJSON_String) {
        // Authorize the device
        pthread_mutex_lock(&cs->mutex);

        char channel[256];
        snprintf(channel, sizeof(channel), "client/dev/%s/%s",
                 dev_uuid->valuestring, "auth123");

        // Check if device already exists
        int found = -1;
        for (int i = 0; i < cs->device_count; i++) {
            if (strcmp(cs->devices[i].dev_uuid, dev_uuid->valuestring) == 0) {
                found = i;
                break;
            }
        }

        if (found < 0 && cs->device_count < MAX_DEVICES) {
            found = cs->device_count++;
        }

        if (found >= 0) {
            DeviceRecord *dev = &cs->devices[found];
            strncpy(dev->dev_uuid, dev_uuid->valuestring, sizeof(dev->dev_uuid) - 1);
            strncpy(dev->auth_channel, channel, sizeof(dev->auth_channel) - 1);
            if (data_types && data_types->type == cJSON_String) {
                strncpy(dev->data_types, data_types->valuestring, sizeof(dev->data_types) - 1);
            }
            dev->auth_time = time(NULL);
            dev->last_update = time(NULL);
            dev->online = 1;
            dev->device_data = NULL;
            dev->network_data = NULL;
            dev->log_data = NULL;

            // Send authorization
            cJSON *resp = cJSON_CreateObject();
            cJSON_AddStringToObject(resp, "dev_uuid", dev_uuid->valuestring);
            cJSON_AddBoolToObject(resp, "authorized", 1);
            cJSON_AddStringToObject(resp, "channel", channel);
            char *str = cJSON_PrintUnformatted(resp);
            send_mqtt_message(CLOUD_PUB_TOPIC, str);
            free(str);
            cJSON_Delete(resp);

            log_msg("Authorized device: %s, channel: %s, data_types: %s",
                    dev_uuid->valuestring, channel, data_types ? data_types->valuestring : "");

            /* 保存设备列表到文件 */
            save_devices_to_file(cs);
        }

        pthread_mutex_unlock(&cs->mutex);
    } else {
        // It's data - parse and store
        cJSON *uuid = cJSON_GetObjectItem(root, "dev_uuid");
        if (uuid && uuid->type == cJSON_String) {
            pthread_mutex_lock(&cs->mutex);

            // Find the device
            for (int i = 0; i < cs->device_count; i++) {
                if (strcmp(cs->devices[i].dev_uuid, uuid->valuestring) == 0) {
                    DeviceRecord *dev = &cs->devices[i];
                    dev->last_update = time(NULL);
                    dev->online = 1;

                    // Determine data type based on topic
                    if (strstr(topic, "/device")) {
                        if (dev->device_data) cJSON_Delete(dev->device_data);
                        dev->device_data = cJSON_Duplicate(root, 1);
                    } else if (strstr(topic, "/network")) {
                        if (dev->network_data) cJSON_Delete(dev->network_data);
                        dev->network_data = cJSON_Duplicate(root, 1);
                    } else if (strstr(topic, "/log")) {
                        if (dev->log_data) cJSON_Delete(dev->log_data);
                        dev->log_data = cJSON_Duplicate(root, 1);
                    }
                    break;
                }
            }

            pthread_mutex_unlock(&cs->mutex);
        }
    }

    cJSON_Delete(root);
    return 1;
}

static void on_disconnect(void *context, MQTTAsync_successData *response) {
    log_msg("Cloud server disconnected");
}

int cloud_server_start(CloudServer *cs) {
    pthread_mutex_lock(&cs->mutex);
    if (cs->running) {
        pthread_mutex_unlock(&cs->mutex);
        return 0;
    }

    char client_id[128];
    snprintf(client_id, sizeof(client_id), "cloud_server_%d", getpid());

    int rc = MQTTAsync_create(&g_client, cs->address, client_id,
                              MQTTCLIENT_PERSISTENCE_NONE, NULL);
    if (rc != MQTTASYNC_SUCCESS) {
        log_msg("Failed to create client, rc=%d", rc);
        pthread_mutex_unlock(&cs->mutex);
        return -1;
    }

    rc = MQTTAsync_setCallbacks(g_client, cs, NULL, on_message, NULL);
    if (rc != MQTTASYNC_SUCCESS) {
        log_msg("Failed to set callbacks, rc=%d", rc);
        MQTTAsync_destroy(&g_client);
        pthread_mutex_unlock(&cs->mutex);
        return -1;
    }

    MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;
    conn_opts.onSuccess = on_connect;
    conn_opts.onFailure = on_connect_failure;
    conn_opts.context = g_client;

    rc = MQTTAsync_connect(g_client, &conn_opts);
    if (rc != MQTTASYNC_SUCCESS) {
        log_msg("Failed to connect, rc=%d", rc);
        MQTTAsync_destroy(&g_client);
        pthread_mutex_unlock(&cs->mutex);
        return -1;
    }

    cs->running = 1;
    pthread_mutex_unlock(&cs->mutex);
    return 0;
}

int cloud_server_stop(CloudServer *cs) {
    pthread_mutex_lock(&cs->mutex);
    if (!cs->running) {
        pthread_mutex_unlock(&cs->mutex);
        return 0;
    }
    cs->running = 0;

    if (g_client) {
        MQTTAsync_disconnectOptions disc_opts = MQTTAsync_disconnectOptions_initializer;
        disc_opts.onSuccess = on_disconnect;
        MQTTAsync_disconnect(g_client, &disc_opts);
        MQTTAsync_destroy(&g_client);
        g_client = NULL;
    }

    pthread_mutex_unlock(&cs->mutex);
    return 0;
}

void cloud_server_destroy(CloudServer *cs) {
    cloud_server_stop(cs);

    pthread_mutex_lock(&cs->mutex);
    for (int i = 0; i < cs->device_count; i++) {
        if (cs->devices[i].device_data) cJSON_Delete(cs->devices[i].device_data);
        if (cs->devices[i].network_data) cJSON_Delete(cs->devices[i].network_data);
        if (cs->devices[i].log_data) cJSON_Delete(cs->devices[i].log_data);
    }
    pthread_mutex_unlock(&cs->mutex);
    pthread_mutex_destroy(&cs->mutex);
}

int cloud_get_devices(CloudServer *cs, DeviceRecord **out_devices, int *out_count) {
    pthread_mutex_lock(&cs->mutex);
    *out_devices = cs->devices;
    *out_count = cs->device_count;
    pthread_mutex_unlock(&cs->mutex);
    return 0;
}

/* ==================== 设备列表持久化 ==================== */
static const char *DEVICES_FILE = "/tmp/cloud_devices.json";

static void save_devices_to_file(CloudServer *cs) {
    pthread_mutex_lock(&cs->mutex);

    cJSON *root = cJSON_CreateObject();
    cJSON *devices = cJSON_CreateArray();

    for (int i = 0; i < cs->device_count; i++) {
        DeviceRecord *dev = &cs->devices[i];
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "dev_uuid", dev->dev_uuid);
        cJSON_AddStringToObject(item, "auth_channel", dev->auth_channel);
        cJSON_AddStringToObject(item, "data_types", dev->data_types);
        cJSON_AddNumberToObject(item, "auth_time", (double)dev->auth_time);
        cJSON_AddNumberToObject(item, "last_update", (double)dev->last_update);
        cJSON_AddNumberToObject(item, "online", dev->online);
        cJSON_AddItemToArray(devices, item);
    }

    cJSON_AddItemToObject(root, "devices", devices);

    FILE *fp = fopen(DEVICES_FILE, "w");
    if (fp) {
        char *str = cJSON_Print(root);
        if (str) {
            fprintf(fp, "%s", str);
            free(str);
        }
        fclose(fp);
        log_msg("Saved %d devices to %s", cs->device_count, DEVICES_FILE);
    }

    cJSON_Delete(root);
    pthread_mutex_unlock(&cs->mutex);
}

static void load_devices_from_file(CloudServer *cs) {
    FILE *fp = fopen(DEVICES_FILE, "r");
    if (!fp) {
        log_msg("No saved devices file found");
        return;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *content = malloc(fsize + 1);
    if (!content) {
        fclose(fp);
        return;
    }

    fread(content, 1, fsize, fp);
    content[fsize] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(content);
    free(content);

    if (!root) {
        log_msg("Failed to parse devices file");
        return;
    }

    cJSON *devices = cJSON_GetObjectItem(root, "devices");
    if (!devices || !cJSON_IsArray(devices)) {
        cJSON_Delete(root);
        return;
    }

    pthread_mutex_lock(&cs->mutex);

    cJSON *item;
    cJSON_ArrayForEach(item, devices) {
        if (cs->device_count >= MAX_DEVICES) break;

        DeviceRecord *dev = &cs->devices[cs->device_count];
        cJSON *uuid = cJSON_GetObjectItem(item, "dev_uuid");
        cJSON *channel = cJSON_GetObjectItem(item, "auth_channel");
        cJSON *types = cJSON_GetObjectItem(item, "data_types");
        cJSON *auth_time = cJSON_GetObjectItem(item, "auth_time");
        cJSON *online = cJSON_GetObjectItem(item, "online");

        if (uuid && uuid->valuestring) {
            strncpy(dev->dev_uuid, uuid->valuestring, sizeof(dev->dev_uuid) - 1);
        }
        if (channel && channel->valuestring) {
            strncpy(dev->auth_channel, channel->valuestring, sizeof(dev->auth_channel) - 1);
        }
        if (types && types->valuestring) {
            strncpy(dev->data_types, types->valuestring, sizeof(dev->data_types) - 1);
        }
        if (auth_time) dev->auth_time = (time_t)auth_time->valuedouble;
        if (online) dev->online = online->valueint;

        dev->device_data = NULL;
        dev->network_data = NULL;
        dev->log_data = NULL;

        cs->device_count++;
    }

    pthread_mutex_unlock(&cs->mutex);
    cJSON_Delete(root);

    log_msg("Loaded %d devices from file", cs->device_count);
}

int cloud_server_init(CloudServer *cs, const char *address) {
    memset(cs, 0, sizeof(CloudServer));
    strncpy(cs->address, address, sizeof(cs->address) - 1);
    cs->qos = 2;
    cs->running = 0;
    cs->device_count = 0;
    pthread_mutex_init(&cs->mutex, NULL);
    g_cs = cs;

    /* 从文件加载已保存的设备 */
    load_devices_from_file(cs);

    return 0;
}
