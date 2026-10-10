#include "device_client.h"
#include <errno.h>
#include <stdarg.h>

static volatile int g_running = 0;
static MQTTAsync g_client = NULL;
static DeviceClient *g_dc = NULL;

static void log_msg(const char *fmt, ...) {
    FILE *fp = fopen("/var/log/work_log/mqtt_plugin.log", "a");
    if (fp) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
        va_list args;
        va_start(args, fmt);
        fprintf(fp, "[%s] [device_client] ", timestamp);
        vfprintf(fp, fmt, args);
        fprintf(fp, "\n");
        fflush(fp);
        fclose(fp);
        va_end(args);
    }
}

static int send_mqtt_message(const char *topic, const char *payload) {
    MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
    MQTTAsync_message msg = MQTTAsync_message_initializer;
    msg.payload = (void *)payload;
    msg.payloadlen = strlen(payload);
    msg.qos = QOS;
    msg.retained = 0;

    MQTTAsync deliveryToken;
    int rc = MQTTAsync_sendMessage(g_client, topic, &msg, &deliveryToken);
    if (rc != MQTTASYNC_SUCCESS) {
        log_msg("Failed to send message to %s, rc=%d", topic, rc);
        return -1;
    }
    return 0;
}

static void on_connect(void *context, MQTTAsync_successData *response) {
    log_msg("Device connected to MQTT broker");
    MQTTAsync client = (MQTTAsync)context;
    MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
    opts.onSuccess = NULL;
    opts.onFailure = NULL;

    // Subscribe to cloud/# for authorization
    int rc = MQTTAsync_subscribe(client, CLIENT_SUB_TOPIC, QOS, &opts);
    if (rc != MQTTASYNC_SUCCESS) {
        log_msg("Failed to subscribe to %s, rc=%d", CLIENT_SUB_TOPIC, rc);
    } else {
        log_msg("Subscribed to %s", CLIENT_SUB_TOPIC);
    }

    // Send auth request
    char topic[128];
    snprintf(topic, sizeof(topic), "client/dev/%s/auth", g_dc->dev_uuid);

    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "dev_uuid", g_dc->dev_uuid);
    cJSON_AddBoolToObject(obj, "auth_request", 1);

    // Add data_types
    char types[64] = {0};
    if (g_dc->data_types & 1) strncat(types, "device,", sizeof(types) - strlen(types) - 1);
    if (g_dc->data_types & 2) strncat(types, "network,", sizeof(types) - strlen(types) - 1);
    if (g_dc->data_types & 4) strncat(types, "log,", sizeof(types) - strlen(types) - 1);
    int len = strlen(types);
    if (len > 0 && types[len-1] == ',') types[len-1] = '\0';
    cJSON_AddStringToObject(obj, "data_types", types);

    char *str = cJSON_PrintUnformatted(obj);
    log_msg("Sending auth request: %s -> %s", topic, str);
    send_mqtt_message(topic, str);
    free(str);
    cJSON_Delete(obj);
}

static void on_connect_failure(void *context, MQTTAsync_failureData *response) {
    log_msg("Connect failed, rc=%d", response ? response->code : -1);
    pthread_mutex_lock(&g_dc->mutex);
    g_dc->auth_status = 0;
    pthread_mutex_unlock(&g_dc->mutex);
    pthread_cond_signal(&g_dc->cond);
}

static int on_message(void *context, char *topic, int topicLen, MQTTAsync_message *message) {
    if (!context || !message || !message->payload) return 1;

    DeviceClient *dc = (DeviceClient *)context;
    char *payload = (char *)message->payload;
    int payloadlen = message->payloadlen;

    log_msg("Received on %s: %.*s", topic, payloadlen, payload);

    cJSON *root = cJSON_Parse(payload);
    if (!root) {
        log_msg("Failed to parse JSON");
        return 1;
    }

    cJSON *authorized = cJSON_GetObjectItem(root, "authorized");
    cJSON *channel = cJSON_GetObjectItem(root, "channel");
    cJSON *dev_uuid = cJSON_GetObjectItem(root, "dev_uuid");

    if (authorized && authorized->type == cJSON_True && channel && channel->type == cJSON_String) {
        pthread_mutex_lock(&dc->mutex);
        strncpy(dc->auth_channel, channel->valuestring, sizeof(dc->auth_channel) - 1);
        dc->auth_channel[sizeof(dc->auth_channel) - 1] = '\0';
        dc->auth_status = 2;  // authorized
        log_msg("Authorization received, channel=%s", dc->auth_channel);
        pthread_mutex_unlock(&dc->mutex);
        pthread_cond_signal(&dc->cond);
    }

    cJSON_Delete(root);
    return 1;
}

static void on_disconnect(void *context, MQTTAsync_successData *response) {
    log_msg("Disconnected");
}

static void on_disconnect_failure(void *context, MQTTAsync_failureData *response) {
    log_msg("Disconnect failed");
}

int device_client_init(DeviceClient *dc, const char *address, const char *dev_uuid, int data_types) {
    memset(dc, 0, sizeof(DeviceClient));
    strncpy(dc->address, address, sizeof(dc->address) - 1);
    strncpy(dc->dev_uuid, dev_uuid, sizeof(dc->dev_uuid) - 1);
    dc->data_types = data_types;
    dc->auth_status = 0;
    pthread_mutex_init(&dc->mutex, NULL);
    pthread_cond_init(&dc->cond, NULL);
    g_dc = dc;
    return 0;
}

int device_client_send_auth(DeviceClient *dc) {
    log_msg("[device_client_send_auth] START, dev_uuid=%s, address=%s", dc->dev_uuid, dc->address);
    pthread_mutex_lock(&dc->mutex);

    // Step 1: Create client
    char client_id[128];
    snprintf(client_id, sizeof(client_id), "device_%s", dc->dev_uuid);
    log_msg("[device_client_send_auth] Step1: Creating client with ID: %s", client_id);

    int rc = MQTTAsync_create(&g_client, dc->address, client_id,
                              MQTTCLIENT_PERSISTENCE_NONE, NULL);
    if (rc != MQTTASYNC_SUCCESS) {
        log_msg("[device_client_send_auth] FAILED: create client, rc=%d", rc);
        pthread_mutex_unlock(&dc->mutex);
        return -1;
    }
    log_msg("[device_client_send_auth] Step1: OK - client created");

    // Step 2: Set callbacks
    log_msg("[device_client_send_auth] Step2: Setting callbacks...");
    rc = MQTTAsync_setCallbacks(g_client, dc, NULL, on_message, NULL);
    if (rc != MQTTASYNC_SUCCESS) {
        log_msg("[device_client_send_auth] FAILED: set callbacks, rc=%d", rc);
        MQTTAsync_destroy(&g_client);
        pthread_mutex_unlock(&dc->mutex);
        return -1;
    }
    log_msg("[device_client_send_auth] Step2: OK - callbacks set");

    // Step 3: Connect
    log_msg("[device_client_send_auth] Step3: Connecting to %s...", dc->address);
    MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;
    conn_opts.onSuccess = on_connect;
    conn_opts.onFailure = on_connect_failure;
    conn_opts.context = g_client;

    rc = MQTTAsync_connect(g_client, &conn_opts);
    if (rc != MQTTASYNC_SUCCESS) {
        log_msg("[device_client_send_auth] FAILED: connect, rc=%d", rc);
        MQTTAsync_destroy(&g_client);
        pthread_mutex_unlock(&dc->mutex);
        return -1;
    }
    log_msg("[device_client_send_auth] Step3: OK - connection started (wait for callback)");

    dc->auth_status = 1;  // sent auth request
    pthread_mutex_unlock(&dc->mutex);

    // Wait for authorization (max 30 seconds)
    log_msg("[device_client_send_auth] Waiting for authorization...");
    pthread_mutex_lock(&dc->mutex);
    struct timespec ts;
    ts.tv_sec = time(NULL) + 30;
    ts.tv_nsec = 0;
    while (dc->auth_status == 1) {
        rc = pthread_cond_timedwait(&dc->cond, &dc->mutex, &ts);
        if (rc == ETIMEDOUT) {
            log_msg("[device_client_send_auth] TIMEOUT: Authorization wait expired");
            dc->auth_status = 0;
            break;
        }
    }
    int status = dc->auth_status;
    log_msg("[device_client_send_auth] END: auth_status=%d", status);
    pthread_mutex_unlock(&dc->mutex);

    return (status == 2) ? 0 : -1;  // 2 = authorized
}

static char *get_device_info_json() {
    struct utsname sys_info;
    uname(&sys_info);

    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "dev_uuid", g_dc->dev_uuid);
    cJSON_AddStringToObject(obj, "hostname", sys_info.nodename);
    cJSON_AddStringToObject(obj, "os", sys_info.sysname);
    cJSON_AddStringToObject(obj, "release", sys_info.release);
    cJSON_AddStringToObject(obj, "version", sys_info.version);
    cJSON_AddStringToObject(obj, "machine", sys_info.machine);
    cJSON_AddStringToObject(obj, "processor", sys_info.machine);

    char *str = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    return str;
}

static char *get_network_info_json() {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "dev_uuid", g_dc->dev_uuid);
    cJSON_AddStringToObject(obj, "ip", "192.168.1.100");  // TODO: real implementation
    cJSON_AddStringToObject(obj, "mac", "00:11:22:33:44:55");
    cJSON_AddStringToObject(obj, "status", "up");

    char *str = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    return str;
}

static char *get_log_info_json() {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "dev_uuid", g_dc->dev_uuid);
    cJSON_AddStringToObject(obj, "last_lines", "System running normally");

    char *str = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    return str;
}

int device_client_start_send(DeviceClient *dc) {
    log_msg("[device_client_start_send] START, waiting for authorization...");
    g_running = 1;

    /* 先等待授权完成 */
    pthread_mutex_lock(&dc->mutex);
    struct timespec ts;
    ts.tv_sec = time(NULL) + 30;
    ts.tv_nsec = 0;
    while (dc->auth_status != 2 && g_running) {
        int rc = pthread_cond_timedwait(&dc->cond, &dc->mutex, &ts);
        if (rc == ETIMEDOUT) {
            log_msg("[device_client_start_send] TIMEOUT: waiting for authorization");
            pthread_mutex_unlock(&dc->mutex);
            return -1;
        }
    }
    pthread_mutex_unlock(&dc->mutex);

    if (!g_running) {
        log_msg("[device_client_start_send] stopped");
        return -1;
    }

    log_msg("[device_client_start_send] Authorization received, starting to send data...");

    char topic[256];
    char *payload;

    while (g_running) {
        pthread_mutex_lock(&dc->mutex);
        if (dc->auth_status != 2) {
            log_msg("[device_client_start_send] auth lost, stopping");
            pthread_mutex_unlock(&dc->mutex);
            break;
        }

        /* 发送设备信息 */
        if (dc->data_types & 1) {
            payload = get_device_info_json();
            snprintf(topic, sizeof(topic), "client/dev/%s/device", dc->dev_uuid);
            log_msg("[device_client_start_send] Sending to %s: %s", topic, payload);
            send_mqtt_message(topic, payload);
            free(payload);
        }

        /* 发送网络信息 */
        if (dc->data_types & 2) {
            payload = get_network_info_json();
            snprintf(topic, sizeof(topic), "client/dev/%s/network", dc->dev_uuid);
            log_msg("[device_client_start_send] Sending to %s: %s", topic, payload);
            send_mqtt_message(topic, payload);
            free(payload);
        }

        /* 发送日志信息 */
        if (dc->data_types & 4) {
            payload = get_log_info_json();
            snprintf(topic, sizeof(topic), "client/dev/%s/log", dc->dev_uuid);
            log_msg("[device_client_start_send] Sending to %s: %s", topic, payload);
            send_mqtt_message(topic, payload);
            free(payload);
        }

        pthread_mutex_unlock(&dc->mutex);

        sleep(10);  /* 每10秒发送一次 */
    }

    log_msg("[device_client_start_send] END");
    return 0;
}

void device_client_stop(DeviceClient *dc) {
    g_running = 0;
}

void device_client_destroy(DeviceClient *dc) {
    if (g_client) {
        MQTTAsync_disconnectOptions disc_opts = MQTTAsync_disconnectOptions_initializer;
        disc_opts.onSuccess = on_disconnect;
        disc_opts.onFailure = on_disconnect_failure;
        MQTTAsync_disconnect(g_client, &disc_opts);
        MQTTAsync_destroy(&g_client);
        g_client = NULL;
    }
    pthread_mutex_destroy(&dc->mutex);
    pthread_cond_destroy(&dc->cond);
}
