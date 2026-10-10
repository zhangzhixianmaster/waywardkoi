#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "client.h"
#include "../common/mqtt_lib.h"
#include "../common/mqtt_cmd.h"

/* ==================== 进程处理函数 ==================== */
/**
 * Cloud 进程处理函数
 * @param ctx MQTT 配置上下文
 * @return 0 成功，-1 失败
 */
int cloud_process_fun(Context *ctx) {
    log_message("cloud_process_fun: starting");

    int ret = mqtt_msg_handle(ctx);
    if (ret != 0) {
        log_message("cloud_process_fun: mqtt_msg_handle failed, ret=%d", ret);
        return -1;
    }

    log_message("cloud_process_fun: mqtt_msg_handle closed");
    return 0;
}

/**
 * Client 进程处理函数
 * @param ctx MQTT 配置上下文
 * @return 0 成功
 */
int client_process_fun(Context *ctx) {
    log_message("client_process_fun: starting");

    int ret = mqtt_msg_handle(ctx);
    if (ret != 0) {
        log_message("client_process_fun: mqtt_msg_handle failed, ret=%d", ret);
    } else {
        log_message("client_process_fun: mqtt_msg_handle closed");
    }

    /* 保持运行直到被停止 */
    while (ctx->running) {
        sleep(10);
    }

    return 0;
}

/* ==================== 主程序 ==================== */
int main(int argc, char *argv[]) {
    (void)argc;  /* unused */
    (void)argv;  /* unused */

    pid_t cloud_pid = -1;
    pid_t client_pid = -1;

    /* 创建命令 socket */
    int cmd_sock = mqtt_cmd_server_create(MQTT_CMD_SOCKET);
    if (cmd_sock < 0) {
        log_message("main: failed to create command socket");
        return -1;
    }
    log_message("main: command socket created at %s", MQTT_CMD_SOCKET);

    /* 清除上次运行的保存状态（当前不需要自启动，每次启动为干净状态） */
    mkdir("/data/work", 0755);
    unlink("/data/work/client_state.b64");
    unlink("/data/work/client_auth_status");
    unlink("/tmp/cloud_devices.json");
    system("rm -f /tmp/cloud_device_*.json 2>/dev/null");
    log_message("main: cleared previous runtime state files");

    /* 加载配置文件 */
    Context *ctx = mqtt_config_load(CONFIG_FILE_PATH);
    if (!ctx) {
        log_message("main: failed to load config");
        close(cmd_sock);
        mqtt_cmd_server_close(MQTT_CMD_SOCKET);
        return -1;
    }
    ctx->running = 1;

    /* 创建管道用于进程间通信 - cloud进程收命令，client进程收命令 */
    int cloud_pipe[2];
    int client_pipe[2];
    if (pipe(cloud_pipe) != 0 || pipe(client_pipe) != 0) {
        log_message("main: pipe failed");
        mqtt_config_free(ctx);
        close(cmd_sock);
        mqtt_cmd_server_close(MQTT_CMD_SOCKET);
        return -1;
    }

    /* Fork Cloud 进程 */
    cloud_pid = fork();
    if (cloud_pid < 0) {
        log_message("main: fork cloud failed");
        mqtt_config_free(ctx);
        close(cmd_sock);
        close(cloud_pipe[0]);
        close(cloud_pipe[1]);
        close(client_pipe[0]);
        close(client_pipe[1]);
        mqtt_cmd_server_close(MQTT_CMD_SOCKET);
        return -1;
    }

    if (cloud_pid == 0) {
        /* Cloud 子进程 - 关闭写端，保留读端 */
        close(cmd_sock);
        close(cloud_pipe[1]);
        close(client_pipe[0]);
        close(client_pipe[1]);
        ctx->fd = cloud_pipe[0];
        ctx->cmd_fd = cloud_pipe[0];
        ctx->flag = CLOUD_FLAG;
        mqtt_config_free(ctx);
        ctx = mqtt_config_load(CONFIG_FILE_PATH);
        ctx->fd = cloud_pipe[0];
        ctx->cmd_fd = cloud_pipe[0];
        ctx->flag = CLOUD_FLAG;
        ctx->running = 1;
        cloud_process_fun(ctx);
        mqtt_config_free(ctx);
        exit(0);
    }

    /* Fork Client 进程 */
    client_pid = fork();
    if (client_pid < 0) {
        log_message("main: fork client failed");
        kill(cloud_pid, SIGTERM);
        mqtt_config_free(ctx);
        close(cmd_sock);
        close(cloud_pipe[0]);
        close(cloud_pipe[1]);
        close(client_pipe[0]);
        close(client_pipe[1]);
        mqtt_cmd_server_close(MQTT_CMD_SOCKET);
        return -1;
    }

    if (client_pid == 0) {
        /* Client 子进程 - 关闭写端，保留读端 */
        close(cmd_sock);
        close(cloud_pipe[0]);
        close(cloud_pipe[1]);
        close(client_pipe[1]);
        ctx->fd = client_pipe[0];
        ctx->cmd_fd = client_pipe[0];
        ctx->flag = CLIENT_FLAG;
        mqtt_config_free(ctx);
        ctx = mqtt_config_load(CONFIG_FILE_PATH);
        ctx->fd = client_pipe[0];
        ctx->cmd_fd = client_pipe[0];
        ctx->flag = CLIENT_FLAG;
        ctx->running = 1;
        client_process_fun(ctx);
        mqtt_config_free(ctx);
        exit(0);
    }

    /* 父进程：关闭读端，保留写端用于发送命令 */
    close(cloud_pipe[0]);
    close(client_pipe[0]);
    ctx->cmd_fd = client_pipe[1];  /* 保存client管道的写端给命令处理函数 */
    g_client_cmd_fd = client_pipe[1];  /* 设置全局变量供mqtt_cmd_handle使用 */

    log_message("main: daemon running, parent handling commands");

    mqtt_cmd_server_loop(cmd_sock);

    /* 清理 */
    close(cmd_sock);
    mqtt_cmd_server_close(MQTT_CMD_SOCKET);
    mqtt_config_free(ctx);

    /* 等待子进程 */
    waitpid(cloud_pid, NULL, 0);
    waitpid(client_pid, NULL, 0);

    log_message("main: daemon exited");
    return 0;
}