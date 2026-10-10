/*
 * SMS 验证码发送模块 - 调用 Python 脚本发送
 *
 * 编译: gcc -shared -fPIC -o libsms.so sms.c -Wall -O2
 *
 * 功能:
 *   - sms_init(): 标记模块就绪
 *   - sms_send_code(phone, code): 调用 sms_script.py 发送短信验证码
 *   - sms_cleanup(): 清理
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <sys/stat.h>

static int g_initialized = 0;

/* 日志：同时写 /var/log/work_log/auth.log 和 stderr */
static void sms_log(const char *fmt, ...) {
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    fprintf(stderr, "[SMS] %s\n", msg);

    mkdir("/var/log/work_log", 0755);
    FILE *fp = fopen("/var/log/work_log/auth.log", "a");
    if (fp) {
        time_t now = time(NULL);
        struct tm *lt = localtime(&now);
        fprintf(fp, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
                lt->tm_hour, lt->tm_min, lt->tm_sec, msg);
        fclose(fp);
    }
}

/* ==================== 公开接口 ==================== */

int sms_init(const char *config_path) {
    (void)config_path;
    if (g_initialized) return 0;
    g_initialized = 1;
    sms_log("使用 Python 脚本发送短信，模块已就绪");
    return 0;
}

int sms_send_code(const char *phone, const char *code) {
    if (!g_initialized) {
        sms_log("模块未初始化");
        return -1;
    }
    if (!phone || !code || strlen(phone) == 0 || strlen(code) == 0) {
        sms_log("参数无效 phone=%s code=%s",
                phone ? phone : "NULL", code ? code : "NULL");
        return -1;
    }

    size_t pl = strlen(phone);
    sms_log("发送: Phone=***%s Code=%s",
            pl > 4 ? phone + pl - 4 : phone, code);

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "/home/workspace/venv/bin/python /home/workspace/libs/sms/sms_send.py %s %s 2>&1",
             phone, code);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        sms_log("popen 失败，无法执行脚本");
        return -1;
    }

    char buf[1024] = {0};
    size_t total = 0;
    while (fgets(buf + total, sizeof(buf) - total - 1, fp))
        total = strlen(buf);
    int exit_code = pclose(fp);

    /* 去除尾部换行 */
    while (total > 0 && (buf[total-1] == '\n' || buf[total-1] == '\r'))
        buf[--total] = '\0';

    sms_log("脚本返回 (exit=%d): %s", exit_code, buf[0] ? buf : "(无输出)");

    /* 检查是否成功: 包含 "success" 且不包含 "ERROR" 或 "fail" */
    if (strstr(buf, "success") && !strstr(buf, "ERROR") && !strstr(buf, "fail")) {
        return 0;
    }

    sms_log("发送失败: %s", buf[0] ? buf : "脚本无输出");
    return -3;
}

int sms_verify_code(const char *phone, const char *code) {
    if (!phone || !code || strlen(phone) == 0 || strlen(code) == 0) {
        sms_log("[VERIFY] 参数无效");
        return -1;
    }

    size_t pl = strlen(phone);
    sms_log("[VERIFY] 校验: Phone=***%s Code=%s",
            pl > 4 ? phone + pl - 4 : phone, code);

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "/home/workspace/venv/bin/python /home/workspace/libs/sms/sms_verify.py %s %s 2>&1",
             phone, code);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        sms_log("[VERIFY] popen 失败");
        return -1;
    }

    char buf[1024] = {0};
    size_t total = 0;
    while (fgets(buf + total, sizeof(buf) - total - 1, fp))
        total = strlen(buf);
    pclose(fp);

    while (total > 0 && (buf[total-1] == '\n' || buf[total-1] == '\r'))
        buf[--total] = '\0';

    sms_log("[VERIFY] 脚本返回: %s", buf[0] ? buf : "(无输出)");

    if (strstr(buf, "success") && !strstr(buf, "ERROR") && !strstr(buf, "fail")) {
        sms_log("[VERIFY] 验证通过");
        return 0;
    }

    sms_log("[VERIFY] 验证失败: %s", buf[0] ? buf : "脚本无输出");
    return -2;
}

void sms_cleanup(void) {
    g_initialized = 0;
    sms_log("模块已清理");
}
