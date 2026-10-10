#include "mqtt_cmd.h"
#include "mqtt_lib.h"

int mqtt_cmd_send(int cmd_type, const char *json_data, MqttCmdResp *resp) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, MQTT_CMD_SOCKET, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    MqttCmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd_type = cmd_type;
    if (json_data) {
        strncpy(cmd.data, json_data, sizeof(cmd.data) - 1);
    }

    // Send command (handle partial writes on stream sockets)
    size_t total_sent = 0;
    while (total_sent < sizeof(cmd)) {
        int n = send(sock, (char*)&cmd + total_sent, sizeof(cmd) - total_sent, 0);
        if (n <= 0) { close(sock); return -1; }
        total_sent += n;
    }

    // Receive response (handle partial reads)
    size_t total_read = 0;
    memset(resp, 0, sizeof(*resp));
    while (total_read < sizeof(*resp)) {
        int n = recv(sock, (char*)resp + total_read, sizeof(*resp) - total_read, 0);
        if (n <= 0) { close(sock); return -1; }
        total_read += n;
    }

    close(sock);
    return 0;
}