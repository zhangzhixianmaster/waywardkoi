/*
 * 设备管理后台 - 多通道统一认证服务
 * 编译: gcc -o login auth.c -I../cjson -lmicrohttpd -lcjson -lcrypto -ldl -lpthread -Wall
 * 运行: ./login               (HTTPS，需证书)
 *       ./login --http        (HTTP 测试)
 *
 * 支持认证通道: password, sms, email, totp, cert, qrcode
 * 支持双因子认证组合
 * 策略驱动: /data/auth_policy.json 控制登录方式和密码策略
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <microhttpd.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <cjson/cJSON.h>

/* Compatibility: older cJSON versions may lack cJSON_IsTrue */
#ifndef cJSON_IsTrue
#define cJSON_IsTrue(x) ((x) && (x)->type == cJSON_True)
#endif

/* ==================== 常量定义 ==================== */
#define PORT 8080
#define ADMINS_FILE       "/data/admins.json"
#define AUTH_CONFIG_FILE  "/etc/auth_config.json"
#define RATE_LIMIT_FILE   "/var/log/work_log/auth_rate.json"

#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 128
#define MAX_TOKEN_SIZE   512
#define MAX_REQUEST_SIZE 8192
#define MAX_PHONE_LEN    32
#define MAX_EMAIL_LEN    96
#define MAX_CODE_LEN     8
#define MAX_UUID_LEN     64
#define MAX_URL_LEN      512
#define MAX_SECRET_LEN   64
#define MAX_FINGERPRINT_LEN 96

#define TOKEN_SECRET    "your-secret-key-change-in-production-2025"
#define TOKEN_EXPIRE_SEC (7 * 24 * 3600)
#define MAX_LOGIN_ATTEMPTS 5
#define LOCKOUT_DURATION   300

/* 默认限流参数 */
#define DEFAULT_SEND_INTERVAL     60
#define DEFAULT_DAILY_MAX_SMS     10
#define DEFAULT_DAILY_MAX_EMAIL   20
#define DEFAULT_FAIL_LOCK         300
#define DEFAULT_MAX_FAIL          3
#define DEFAULT_CODE_EXPIRE       300
#define DEFAULT_CODE_LENGTH       6
#define DEFAULT_QR_EXPIRE         120
#define DEFAULT_HTTP_TIMEOUT_SMS  5
#define DEFAULT_HTTP_TIMEOUT_EMAIL 8

#define CLEANUP_INTERVAL 60

/* ==================== 数据结构 ==================== */

/* 认证通道枚举 */
typedef enum {
    CHANNEL_NONE = 0,
    CHANNEL_PASSWORD,
    CHANNEL_SMS,
    CHANNEL_EMAIL,
    CHANNEL_TOTP,
    CHANNEL_CERT,
    CHANNEL_QRCODE
} AuthChannel;

/* 通道动态库接口（编译时链接，运行时 init 判可用性） */
extern int  sms_init(const char *cfg);
extern int  sms_send_code(const char *phone, const char *code);
extern int  sms_verify_code(const char *phone, const char *code);
extern void sms_cleanup(void);

extern int  email_init(const char *cfg);
extern int  email_send_code(const char *to, const char *username, const char *code);
extern void email_cleanup(void);

extern int  totp_init(const char *cfg);
extern int  totp_verify(const char *secret, const char *code);
extern int  totp_generate_secret(char *out, size_t len);
extern void totp_cleanup(void);

extern int  cert_init(const char *cfg);
extern int  cert_verify(const char *fingerprint1, const char *fingerprint2);
extern void cert_cleanup(void);

/* 验证码存储 */
typedef struct CodeNode {
    char key[128];          /* "channel:target" */
    char code[MAX_CODE_LEN];
    time_t expire_time;
    struct CodeNode *next;
} CodeNode;

/* 发送限流 */
typedef struct SendLimitNode {
    char key[128];
    time_t last_send;
    int daily_count;
    char date[9];
    struct SendLimitNode *next;
} SendLimitNode;

/* 失败限流 */
typedef struct FailLimitNode {
    char key[128];
    int fail_count;
    time_t lock_until;
    struct FailLimitNode *next;
} FailLimitNode;

/* 二维码会话 */
typedef struct {
    char qr_id[MAX_UUID_LEN];
    char username[MAX_USERNAME_LEN];
    int status;             /* 0=待扫描, 1=已扫码待确认, 2=已确认, -1=过期 */
    time_t created_at;
    time_t expires_at;
    char token[MAX_TOKEN_SIZE];
} QRCodeSession;

/* 限流配置 */
typedef struct {
    int send_interval;
    int daily_max;
    int max_fail_attempts;
    int fail_lock_duration;
    int http_timeout;
} ChannelRateLimit;

/* 全局配置 */
typedef struct {
    int code_expire_seconds;
    int code_length;
    int qr_expire_seconds;
    ChannelRateLimit sms_limit;
    ChannelRateLimit email_limit;
    ChannelRateLimit totp_limit;
} AuthConfig;

/* 策略数据结构 */
typedef struct {
    char login_policy[64];
    char updated_at[64];
    int updated_by;
    /* 密码策略 */
    int pw_min_length;
    int pw_require_uppercase;
    int pw_require_lowercase;
    int pw_require_digit;
    int pw_require_special;
    int pw_forbid_username;
    int pw_forbid_common;
    int pw_history_count;
} AuthPolicy;

/* IP速率限制（密码登录） */
typedef struct {
    char ip[64];
    int attempts;
    time_t last_attempt;
    time_t lockout_until;
} RateLimitEntry;

/* ==================== 全局状态 ==================== */
static volatile int g_running = 1;

/* 通道可用性标记 */
static int g_sms_loaded   = 0;
static int g_email_loaded = 0;
static int g_totp_loaded  = 0;
static int g_cert_loaded  = 0;

/* 验证码/限流存储 */
static CodeNode      *g_code_table   = NULL;
static SendLimitNode *g_send_limits  = NULL;
static FailLimitNode *g_fail_limits  = NULL;
static QRCodeSession *g_qr_sessions  = NULL;
static int g_qr_session_count = 0;
#define MAX_QR_SESSIONS 256

static AuthConfig  g_config;
static AuthPolicy  g_policy;
static cJSON      *g_module_menu = NULL;

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_cleanup_thread;
static int g_cleanup_started = 0;

/* IP速率限制 */
static RateLimitEntry *g_rate_limits = NULL;
static int g_rate_limit_count = 0;

/* ==================== 日志 ==================== */
#define AUTH_LOG_FILE "/var/log/work_log/auth.log"
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void auth_log(const char *level, const char *fmt, ...) {
    pthread_mutex_lock(&g_log_mutex);

    /* 先格式化到 buffer，然后同时写文件和 stderr */
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    FILE *fp = fopen(AUTH_LOG_FILE, "a");
    if (fp) {
        time_t now = time(NULL);
        struct tm *lt = localtime(&now);
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", lt);
        fprintf(fp, "[%s] [%s] %s\n", ts, level, msg);
        fflush(fp);
        fclose(fp);
    }
    /* 同时输出到 stderr */
    fprintf(stderr, "[%s] %s\n", level, msg);

    pthread_mutex_unlock(&g_log_mutex);
}

#define LOG_INFO(fmt, ...)  auth_log("INFO", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) auth_log("ERROR", fmt, ##__VA_ARGS__)

/* ==================== 安全辅助函数 ==================== */
static void safe_strcpy(char *dst, const char *src, size_t dst_size) {
    if (!dst || !src || dst_size == 0) return;
    size_t len = strlen(src);
    if (len >= dst_size) len = dst_size - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* 前向声明：操作审计日志（定义在 main 之前）*/
static void write_audit_log(const char *user, const char *action,
                            const char *ip, int success);

static int const_time_memcmp(const void *a, const void *b, size_t len) {
    const unsigned char *pa = a, *pb = b;
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) diff |= pa[i] ^ pb[i];
    return diff == 0;
}

static void sha256_hash(unsigned char *output, const unsigned char *input, size_t len) {
    SHA256(input, len, output);
}

static void hmac_sha256(unsigned char *output, const char *key, const char *data) {
    unsigned int len = 32;
    HMAC(EVP_sha256(), key, strlen(key), (unsigned char*)data, strlen(data), output, &len);
}

static void generate_random_hex(char *output, size_t len) {
    unsigned char *rand_bytes = malloc(len / 2);
    if (!rand_bytes) return;
    if (RAND_bytes(rand_bytes, (int)(len / 2)) != 1) {
        /* RAND_bytes 失败：用 0 填充，避免使用未初始化内存 */
        memset(rand_bytes, 0, len / 2);
    }
    for (size_t i = 0; i < len / 2; i++)
        sprintf(output + i * 2, "%02x", rand_bytes[i]);
    free(rand_bytes);
}

static void generate_uuid(char *out, size_t len) {
    /* 简单UUID: 32字符随机hex */
    if (len < 33) return;
    generate_random_hex(out, 32);
    out[32] = '\0';
}

static int verify_password(const char *password, const char *stored_hash) {
    unsigned char hash[32];
    sha256_hash(hash, (const unsigned char*)password, strlen(password));
    char hash_str[65];
    for (int i = 0; i < 32; i++) sprintf(hash_str + i * 2, "%02x", hash[i]);
    return const_time_memcmp(hash_str, stored_hash, 64);
}

/* ==================== 配置文件读取 ==================== */
static char* read_file_content(const char *filename, long *out_len) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (len <= 0) { fclose(fp); if (out_len) *out_len = 0; return NULL; }
    char *buf = malloc(len + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t nread = fread(buf, 1, len, fp);
    if (nread != (size_t)len) {
        /* 读取不足：填充剩余部分为零 */
        memset(buf + nread, 0, len - nread + 1);
    } else {
        buf[len] = '\0';
    }
    fclose(fp);
    if (out_len) *out_len = len;
    return buf;
}

/* ==================== 统一 JSON 配置加载 ==================== */
/*
 * 从 /etc/auth_config.json 一次性加载所有配置:
 *   common, channels.*, login_policy, password_policy, menu
 */
static void load_config(void) {
    /* ---- 设置默认值 ---- */
    g_config.code_expire_seconds = DEFAULT_CODE_EXPIRE;
    g_config.code_length         = DEFAULT_CODE_LENGTH;
    g_config.qr_expire_seconds   = DEFAULT_QR_EXPIRE;
    g_config.sms_limit.send_interval   = DEFAULT_SEND_INTERVAL;
    g_config.sms_limit.daily_max       = DEFAULT_DAILY_MAX_SMS;
    g_config.sms_limit.max_fail_attempts = DEFAULT_MAX_FAIL;
    g_config.sms_limit.fail_lock_duration = DEFAULT_FAIL_LOCK;
    g_config.sms_limit.http_timeout    = DEFAULT_HTTP_TIMEOUT_SMS;
    g_config.email_limit.send_interval = DEFAULT_SEND_INTERVAL;
    g_config.email_limit.daily_max     = DEFAULT_DAILY_MAX_EMAIL;
    g_config.email_limit.max_fail_attempts = DEFAULT_MAX_FAIL;
    g_config.email_limit.fail_lock_duration = DEFAULT_FAIL_LOCK;
    g_config.email_limit.http_timeout  = DEFAULT_HTTP_TIMEOUT_EMAIL;
    g_config.totp_limit.max_fail_attempts = DEFAULT_MAX_FAIL;
    g_config.totp_limit.fail_lock_duration = DEFAULT_FAIL_LOCK;

    memset(&g_policy, 0, sizeof(g_policy));
    strcpy(g_policy.login_policy, "password_only");
    g_policy.pw_min_length = 8;

    /* 构建默认菜单 */
    if (g_module_menu) cJSON_Delete(g_module_menu);
    g_module_menu = cJSON_CreateObject();
    cJSON *def_arr = cJSON_CreateArray();
    cJSON *it;
    it = cJSON_CreateObject(); cJSON_AddStringToObject(it, "id", "dashboard"); cJSON_AddStringToObject(it, "name", "首页"); cJSON_AddStringToObject(it, "icon", "📊"); cJSON_AddStringToObject(it, "link", "/projects/device_manager/pages/dashboard.html"); cJSON_AddItemToArray(def_arr, it);
    it = cJSON_CreateObject(); cJSON_AddStringToObject(it, "id", "admin"); cJSON_AddStringToObject(it, "name", "管理员"); cJSON_AddStringToObject(it, "icon", "👥"); cJSON_AddStringToObject(it, "link", "/projects/device_manager/pages/admin.html"); cJSON *r = cJSON_CreateArray(); cJSON_AddItemToArray(r, cJSON_CreateString("admin")); cJSON_AddItemToObject(it, "role", r); cJSON_AddItemToArray(def_arr, it);
    it = cJSON_CreateObject(); cJSON_AddStringToObject(it, "id", "mqtt"); cJSON_AddStringToObject(it, "name", "安全云服务"); cJSON_AddStringToObject(it, "icon", "☁️"); cJSON_AddStringToObject(it, "link", "/projects/device_manager/pages/mqtt.html"); cJSON_AddItemToArray(def_arr, it);
    it = cJSON_CreateObject(); cJSON_AddStringToObject(it, "id", "policy"); cJSON_AddStringToObject(it, "name", "安全策略"); cJSON_AddStringToObject(it, "icon", "🔐"); cJSON_AddStringToObject(it, "link", "/projects/device_manager/pages/policy.html"); r = cJSON_CreateArray(); cJSON_AddItemToArray(r, cJSON_CreateString("admin")); cJSON_AddItemToObject(it, "role", r); cJSON_AddItemToArray(def_arr, it);
    it = cJSON_CreateObject(); cJSON_AddStringToObject(it, "id", "certs"); cJSON_AddStringToObject(it, "name", "证书管理"); cJSON_AddStringToObject(it, "icon", "📜"); cJSON_AddStringToObject(it, "link", "/projects/device_manager/pages/certs.html"); r = cJSON_CreateArray(); cJSON_AddItemToArray(r, cJSON_CreateString("admin")); cJSON_AddItemToObject(it, "role", r); cJSON_AddItemToArray(def_arr, it);
    it = cJSON_CreateObject(); cJSON_AddStringToObject(it, "id", "logs"); cJSON_AddStringToObject(it, "name", "操作日志"); cJSON_AddStringToObject(it, "icon", "📋"); cJSON_AddStringToObject(it, "link", "/projects/device_manager/pages/logs.html"); r = cJSON_CreateArray(); cJSON_AddItemToArray(r, cJSON_CreateString("admin")); cJSON_AddItemToArray(r, cJSON_CreateString("auditor")); cJSON_AddItemToObject(it, "role", r); cJSON_AddItemToArray(def_arr, it);
    cJSON_AddItemToObject(g_module_menu, "menu", def_arr);

    /* ---- 读取 JSON 文件 ---- */
    FILE *fp = fopen(AUTH_CONFIG_FILE, "r");
    if (!fp) {
        fprintf(stderr, "[AUTH] Config %s not found, using defaults\n", AUTH_CONFIG_FILE);
        return;
    }
    fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
    if (sz <= 0) { fclose(fp); return; }
    char *buf = malloc(sz + 1);
    if (!buf) { fclose(fp); return; }
    fread(buf, 1, sz, fp); buf[sz] = '\0'; fclose(fp);
    cJSON *root = cJSON_Parse(buf); free(buf);
    if (!root) { fprintf(stderr, "[AUTH] JSON parse error, using defaults\n"); return; }

    /* ---- common ---- */
    cJSON *common = cJSON_GetObjectItem(root, "common");
    if (common) {
        cJSON *v;
        v = cJSON_GetObjectItem(common, "code_expire_seconds"); if (v) g_config.code_expire_seconds = (int)v->valuedouble;
        v = cJSON_GetObjectItem(common, "code_length"); if (v) g_config.code_length = (int)v->valuedouble;
        v = cJSON_GetObjectItem(common, "qr_expire_seconds"); if (v) g_config.qr_expire_seconds = (int)v->valuedouble;
    }

    /* ---- channels ---- */
    cJSON *chs = cJSON_GetObjectItem(root, "channels");
    if (chs) {
        /* sms rate limits */
        cJSON *sms = cJSON_GetObjectItem(chs, "sms");
        if (sms) {
            cJSON *v;
            v = cJSON_GetObjectItem(sms, "send_interval"); if (v) g_config.sms_limit.send_interval = (int)v->valuedouble;
            v = cJSON_GetObjectItem(sms, "daily_max"); if (v) g_config.sms_limit.daily_max = (int)v->valuedouble;
            v = cJSON_GetObjectItem(sms, "max_fail_attempts"); if (v) g_config.sms_limit.max_fail_attempts = (int)v->valuedouble;
            v = cJSON_GetObjectItem(sms, "fail_lock_duration"); if (v) g_config.sms_limit.fail_lock_duration = (int)v->valuedouble;
            v = cJSON_GetObjectItem(sms, "http_timeout"); if (v) g_config.sms_limit.http_timeout = (int)v->valuedouble;
        }
        /* email rate limits */
        cJSON *email = cJSON_GetObjectItem(chs, "email");
        if (email) {
            cJSON *v;
            v = cJSON_GetObjectItem(email, "send_interval"); if (v) g_config.email_limit.send_interval = (int)v->valuedouble;
            v = cJSON_GetObjectItem(email, "daily_max"); if (v) g_config.email_limit.daily_max = (int)v->valuedouble;
            v = cJSON_GetObjectItem(email, "max_fail_attempts"); if (v) g_config.email_limit.max_fail_attempts = (int)v->valuedouble;
            v = cJSON_GetObjectItem(email, "fail_lock_duration"); if (v) g_config.email_limit.fail_lock_duration = (int)v->valuedouble;
            v = cJSON_GetObjectItem(email, "http_timeout"); if (v) g_config.email_limit.http_timeout = (int)v->valuedouble;
        }
        /* totp rate limits */
        cJSON *totp = cJSON_GetObjectItem(chs, "totp");
        if (totp) {
            cJSON *v;
            v = cJSON_GetObjectItem(totp, "max_fail_attempts"); if (v) g_config.totp_limit.max_fail_attempts = (int)v->valuedouble;
            v = cJSON_GetObjectItem(totp, "fail_lock_duration"); if (v) g_config.totp_limit.fail_lock_duration = (int)v->valuedouble;
        }
    }

    /* ---- login_policy ---- */
    cJSON *lp = cJSON_GetObjectItem(root, "login_policy");
    if (lp && cJSON_IsString(lp)) safe_strcpy(g_policy.login_policy, lp->valuestring, sizeof(g_policy.login_policy));
    cJSON *ua = cJSON_GetObjectItem(root, "updated_at");
    if (ua) safe_strcpy(g_policy.updated_at, ua->valuestring, sizeof(g_policy.updated_at));
    cJSON *ub = cJSON_GetObjectItem(root, "updated_by");
    if (ub) g_policy.updated_by = (int)ub->valuedouble;

    /* ---- password_policy ---- */
    cJSON *pp = cJSON_GetObjectItem(root, "password_policy");
    if (pp) {
        cJSON *v;
        v = cJSON_GetObjectItem(pp, "min_length"); if (v) g_policy.pw_min_length = (int)v->valuedouble;
        v = cJSON_GetObjectItem(pp, "require_uppercase"); if (v) g_policy.pw_require_uppercase = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp, "require_lowercase"); if (v) g_policy.pw_require_lowercase = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp, "require_digit"); if (v) g_policy.pw_require_digit = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp, "require_special"); if (v) g_policy.pw_require_special = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp, "forbid_username"); if (v) g_policy.pw_forbid_username = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp, "forbid_common"); if (v) g_policy.pw_forbid_common = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp, "history_count"); if (v) g_policy.pw_history_count = (int)v->valuedouble;
    }

    /* ---- menu (覆盖默认) ---- */
    cJSON *menu_arr = cJSON_GetObjectItem(root, "menu");
    if (menu_arr && cJSON_IsArray(menu_arr)) {
        cJSON_DeleteItemFromObject(g_module_menu, "menu");
        cJSON_AddItemToObject(g_module_menu, "menu", cJSON_Duplicate(menu_arr, 1));
    }

    cJSON_Delete(root);
    printf("[AUTH] Config loaded: policy=%s expire=%d len=%d qr=%d\n",
           g_policy.login_policy, g_config.code_expire_seconds,
           g_config.code_length, g_config.qr_expire_seconds);
}

/* ==================== 动态库初始化（编译时链接） ==================== */
/*
 * 调用各库的 xxx_init()，返回 0 表示通道可用。
 * init 失败不导致程序退出，只是标记该通道不可用（降级）。
 */

static int init_channel_sms(void) {
    if (sms_init(AUTH_CONFIG_FILE) == 0) { g_sms_loaded = 1; printf("[AUTH] sms channel loaded\n"); return 0; }
    fprintf(stderr, "[AUTH] sms: init failed, channel disabled\n"); return -1;
}
static int init_channel_email(void) {
    if (email_init(AUTH_CONFIG_FILE) == 0) { g_email_loaded = 1; printf("[AUTH] email channel loaded\n"); return 0; }
    fprintf(stderr, "[AUTH] email: init failed, channel disabled\n"); return -1;
}
static int init_channel_totp(void) {
    if (totp_init(AUTH_CONFIG_FILE) == 0) { g_totp_loaded = 1; printf("[AUTH] totp channel loaded\n"); return 0; }
    fprintf(stderr, "[AUTH] totp: init failed, channel disabled\n"); return -1;
}
static int init_channel_cert(void) {
    if (cert_init(AUTH_CONFIG_FILE) == 0) { g_cert_loaded = 1; printf("[AUTH] cert channel loaded\n"); return 0; }
    fprintf(stderr, "[AUTH] cert: init failed, channel disabled\n"); return -1;
}

static int is_channel_available(const char *channel_name) {
    if (strcmp(channel_name, "password") == 0) return 1;
    if (strcmp(channel_name, "sms") == 0)     return g_sms_loaded;
    if (strcmp(channel_name, "email") == 0)   return g_email_loaded;
    if (strcmp(channel_name, "totp") == 0)    return g_totp_loaded;
    if (strcmp(channel_name, "cert") == 0)    return g_cert_loaded;
    if (strcmp(channel_name, "qrcode") == 0)  return 1;
    return 0;
}

/* 策略匹配：支持 | 分隔的多策略，每段再按 _ 匹配
 * 例如 "password_only|sms_only|password_and_sms" */
static int is_channel_in_policy(const char *policy, const char *channel) {
    if (!policy || !channel) return 0;
    char buf[256]; safe_strcpy(buf, policy, sizeof(buf));
    /* 按 | 拆分每个策略 */
    char *strategy = strtok(buf, "|");
    while (strategy) {
        /* 在每个策略中按 _ 拆分查找 channel */
        size_t ch_len = strlen(channel);
        const char *pos = strategy;
        while (*pos) {
            const char *sep = strchr(pos, '_');
            size_t seg_len = sep ? (size_t)(sep - pos) : strlen(pos);
            if (seg_len == ch_len && strncmp(pos, channel, ch_len) == 0)
                return 1;
            if (!sep) break;
            pos = sep + 1;
        }
        strategy = strtok(NULL, "|");
    }
    return 0;
}

/* 检查通道是否可作为独立因子使用（非仅双因子） */
static int is_standalone_channel(const char *policy, const char *channel, const char *exclude_prefix) {
    char buf[256]; safe_strcpy(buf, policy, sizeof(buf));
    char *s = strtok(buf, "|");
    while (s) {
        /* 跳过以 exclude_prefix 开头的策略段（如 password_and_*） */
        if (exclude_prefix && strncmp(s, exclude_prefix, strlen(exclude_prefix)) == 0) {
            s = strtok(NULL, "|");
            continue;
        }
        /* 在当前策略段中查找 channel */
        const char *pos = s;
        while (*pos) {
            const char *sep = strchr(pos, '_');
            size_t seg_len = sep ? (size_t)(sep - pos) : strlen(pos);
            size_t ch_len = strlen(channel);
            if (seg_len == ch_len && strncmp(pos, channel, ch_len) == 0)
                return 1;
            if (!sep) break;
            pos = sep + 1;
        }
        s = strtok(NULL, "|");
    }
    return 0;
}

static cJSON* build_available_channels(void) {
    cJSON *arr = cJSON_CreateArray();
    const char *policy = g_policy.login_policy;
    /* 密码随时可用 */
    if (is_channel_in_policy(policy, "password")) cJSON_AddItemToArray(arr, cJSON_CreateString("password"));
    /* sms/email/qrcode：检查是否作为独立通道存在（不在 password_and_ 策略中的才算） */
    if (is_standalone_channel(policy, "sms", "password_and_") && g_sms_loaded) cJSON_AddItemToArray(arr, cJSON_CreateString("sms"));
    if (is_standalone_channel(policy, "email", "password_and_") && g_email_loaded) cJSON_AddItemToArray(arr, cJSON_CreateString("email"));
    if (is_standalone_channel(policy, "totp", "password_and_") && g_totp_loaded) cJSON_AddItemToArray(arr, cJSON_CreateString("totp"));
    if (is_standalone_channel(policy, "cert", "password_and_") && g_cert_loaded) cJSON_AddItemToArray(arr, cJSON_CreateString("cert"));
    if (is_standalone_channel(policy, "qrcode", "password_and_")) cJSON_AddItemToArray(arr, cJSON_CreateString("qrcode"));
    return arr;
}

/* 返回前端 METHOD_CONFIG 的 key 列表，含双因子组合 */
static cJSON* build_available_methods(void) {
    cJSON *arr = cJSON_CreateArray();
    const char *p = g_policy.login_policy;
    char buf[256]; safe_strcpy(buf, p, sizeof(buf));
    char *s = strtok(buf, "|");
    while (s) {
        /* 策略名 → METHOD_CONFIG key 映射 */
        if (strcmp(s, "password_only") == 0) cJSON_AddItemToArray(arr, cJSON_CreateString("password"));
        else if (strcmp(s, "sms_only") == 0 && g_sms_loaded) cJSON_AddItemToArray(arr, cJSON_CreateString("sms"));
        else if (strcmp(s, "email_only") == 0 && g_email_loaded) cJSON_AddItemToArray(arr, cJSON_CreateString("email"));
        else if (strcmp(s, "totp_only") == 0 && g_totp_loaded) cJSON_AddItemToArray(arr, cJSON_CreateString("totp"));
        else if (strcmp(s, "cert_only") == 0 && g_cert_loaded) cJSON_AddItemToArray(arr, cJSON_CreateString("cert"));
        else if (strcmp(s, "qrcode_only") == 0) cJSON_AddItemToArray(arr, cJSON_CreateString("qrcode"));
        else if (strcmp(s, "cert_only") == 0 && g_cert_loaded) cJSON_AddItemToArray(arr, cJSON_CreateString("cert"));
        else if (strcmp(s, "password_and_sms") == 0 && g_sms_loaded) cJSON_AddItemToArray(arr, cJSON_CreateString("password_sms"));
        else if (strcmp(s, "password_and_email") == 0 && g_email_loaded) cJSON_AddItemToArray(arr, cJSON_CreateString("password_email"));
        else if (strcmp(s, "password_and_totp") == 0 && g_totp_loaded) cJSON_AddItemToArray(arr, cJSON_CreateString("password_totp"));
        else if (strcmp(s, "password_and_cert") == 0 && g_cert_loaded) cJSON_AddItemToArray(arr, cJSON_CreateString("password_cert"));
        s = strtok(NULL, "|");
    }
    /* 确保密码始终存在 */
    if (cJSON_GetArraySize(arr) == 0)
        cJSON_AddItemToArray(arr, cJSON_CreateString("password"));
    return arr;
}

/* 检查是否有双因子策略（任意一段包含 password_and_）*/
static int is_dual_factor_policy(void) {
    char buf[256]; safe_strcpy(buf, g_policy.login_policy, sizeof(buf));
    LOG_INFO("is_dual: policy='%s'", g_policy.login_policy);
    char *s = strtok(buf, "|");
    while (s) {
        LOG_INFO("is_dual: checking segment='%s'", s);
        if (strncmp(s, "password_and_", 13) == 0) {
            LOG_INFO("is_dual: MATCH found=%s", s);
            return 1;
        }
        s = strtok(NULL, "|");
    }
    LOG_INFO("is_dual: no match, returns 0");
    return 0;
}

/* 获取双因子通道（返回第一个匹配的密码+XXX策略中的XXX）*/
static const char* get_dual_channel(void) {
    static char dual_ch[32];
    char buf[256]; safe_strcpy(buf, g_policy.login_policy, sizeof(buf));
    char *s = strtok(buf, "|");
    while (s) {
        if (strncmp(s, "password_and_", 13) == 0) {
            const char *ch = s + 13;
            /* 截取到下一个 _ 或 | 或结尾 */
            size_t len = 0;
            while (ch[len] && ch[len] != '_' && ch[len] != '|') len++;
            if (len > 0 && len < sizeof(dual_ch)) {
                memcpy(dual_ch, ch, len);
                dual_ch[len] = '\0';
                return dual_ch;
            }
        }
        s = strtok(NULL, "|");
    }
    return NULL;
}

/* ==================== 管理员数据查找 ==================== */
static cJSON* load_admins_json(void) {
    FILE *fp = fopen(ADMINS_FILE, "r");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
    if (sz <= 0) { fclose(fp); return NULL; }
    char *buf = malloc(sz + 1);
    if (!buf) { fclose(fp); return NULL; }
    fread(buf, 1, sz, fp); buf[sz] = '\0'; fclose(fp);
    cJSON *arr = cJSON_Parse(buf); free(buf);
    return arr;
}

static cJSON* find_admin_by_username(const char *username) {
    cJSON *arr = load_admins_json();
    if (!arr) return NULL;
    cJSON *found = NULL, *child;
    cJSON_ArrayForEach(child, arr) {
        cJSON *u = cJSON_GetObjectItem(child, "username");
        if (u && cJSON_IsString(u) && strcmp(u->valuestring, username) == 0) {
            found = cJSON_Duplicate(child, 1);
            break;
        }
    }
    cJSON_Delete(arr);
    return found;
}

static cJSON* find_admin_by_field(const char *field, const char *value) {
    cJSON *arr = load_admins_json();
    if (!arr) return NULL;
    cJSON *found = NULL, *child;
    cJSON_ArrayForEach(child, arr) {
        cJSON *f = cJSON_GetObjectItem(child, field);
        if (f && cJSON_IsString(f) && strlen(f->valuestring) > 0 &&
            strcmp(f->valuestring, value) == 0) {
            found = cJSON_Duplicate(child, 1);
            break;
        }
    }
    cJSON_Delete(arr);
    return found;
}

/* ==================== 验证码管理 ==================== */
static void store_code(const char *key, const char *code) {
    pthread_mutex_lock(&g_mutex);
    CodeNode *n = g_code_table;
    while (n) {
        if (strcmp(n->key, key) == 0) {
            strncpy(n->code, code, MAX_CODE_LEN - 1);
            n->code[MAX_CODE_LEN - 1] = '\0';
            n->expire_time = time(NULL) + g_config.code_expire_seconds;
            pthread_mutex_unlock(&g_mutex);
            return;
        }
        n = n->next;
    }
    CodeNode *nn = calloc(1, sizeof(CodeNode));
    if (!nn) { pthread_mutex_unlock(&g_mutex); return; }
    safe_strcpy(nn->key, key, sizeof(nn->key));
    safe_strcpy(nn->code, code, sizeof(nn->code));
    nn->expire_time = time(NULL) + g_config.code_expire_seconds;
    nn->next = g_code_table;
    g_code_table = nn;
    pthread_mutex_unlock(&g_mutex);
}

static int verify_and_consume_code(const char *key, const char *code) {
    pthread_mutex_lock(&g_mutex);
    CodeNode *prev = NULL, *n = g_code_table;
    time_t now = time(NULL);
    while (n) {
        if (strcmp(n->key, key) == 0) {
            if (n->expire_time < now) { pthread_mutex_unlock(&g_mutex); return 0; }
            size_t cl = strlen(code), nl = strlen(n->code);
            if (cl == nl && const_time_memcmp(n->code, code, cl)) {
                if (prev) prev->next = n->next;
                else g_code_table = n->next;
                free(n);
                pthread_mutex_unlock(&g_mutex);
                return 1;
            }
            pthread_mutex_unlock(&g_mutex); return 0;
        }
        prev = n; n = n->next;
    }
    pthread_mutex_unlock(&g_mutex);
    return 0;
}

/* ==================== 限流管理 ==================== */
static int check_send_limit(const char *key, ChannelRateLimit *lim) {
    pthread_mutex_lock(&g_mutex);
    time_t now = time(NULL);
    char today[9]; struct tm *lt = localtime(&now);
    snprintf(today, sizeof(today), "%04d%02d%02d", lt->tm_year+1900, lt->tm_mon+1, lt->tm_mday);
    SendLimitNode *n = g_send_limits;
    while (n) {
        if (strcmp(n->key, key) == 0) {
            if (strcmp(n->date, today) != 0) { n->daily_count = 0; strncpy(n->date, today, sizeof(n->date)-1); }
            if (now - n->last_send < lim->send_interval) { pthread_mutex_unlock(&g_mutex); return -1; }
            if (n->daily_count >= lim->daily_max) { pthread_mutex_unlock(&g_mutex); return -2; }
            pthread_mutex_unlock(&g_mutex); return 0;
        }
        n = n->next;
    }
    pthread_mutex_unlock(&g_mutex); return 0;
}

static void record_send_attempt(const char *key) {
    pthread_mutex_lock(&g_mutex);
    time_t now = time(NULL);
    char today[9]; struct tm *lt = localtime(&now);
    snprintf(today, sizeof(today), "%04d%02d%02d", lt->tm_year+1900, lt->tm_mon+1, lt->tm_mday);
    SendLimitNode *n = g_send_limits;
    while (n) {
        if (strcmp(n->key, key) == 0) {
            if (strcmp(n->date, today) != 0) { n->daily_count = 0; strncpy(n->date, today, sizeof(n->date)-1); }
            n->last_send = now; n->daily_count++; pthread_mutex_unlock(&g_mutex); return;
        }
        n = n->next;
    }
    SendLimitNode *nn = calloc(1, sizeof(SendLimitNode));
    if (!nn) { pthread_mutex_unlock(&g_mutex); return; }
    safe_strcpy(nn->key, key, sizeof(nn->key));
    nn->last_send = now; nn->daily_count = 1;
    strncpy(nn->date, today, sizeof(nn->date)-1);
    nn->next = g_send_limits; g_send_limits = nn;
    pthread_mutex_unlock(&g_mutex);
}

static int check_fail_lock(const char *key, ChannelRateLimit *lim) {
    pthread_mutex_lock(&g_mutex);
    FailLimitNode *n = g_fail_limits;
    time_t now = time(NULL);
    while (n) {
        if (strcmp(n->key, key) == 0) {
            if (n->lock_until > now) { pthread_mutex_unlock(&g_mutex); return -1; }
            if (n->lock_until > 0 && n->lock_until <= now) { n->fail_count = 0; n->lock_until = 0; }
            pthread_mutex_unlock(&g_mutex); return 0;
        }
        n = n->next;
    }
    pthread_mutex_unlock(&g_mutex); return 0;
}

static void record_fail_attempt(const char *key, ChannelRateLimit *lim) {
    pthread_mutex_lock(&g_mutex);
    time_t now = time(NULL);
    FailLimitNode *n = g_fail_limits;
    while (n) {
        if (strcmp(n->key, key) == 0) {
            n->fail_count++;
            if (n->fail_count >= lim->max_fail_attempts) {
                n->lock_until = now + lim->fail_lock_duration;
            }
            pthread_mutex_unlock(&g_mutex); return;
        }
        n = n->next;
    }
    FailLimitNode *nn = calloc(1, sizeof(FailLimitNode));
    if (!nn) { pthread_mutex_unlock(&g_mutex); return; }
    safe_strcpy(nn->key, key, sizeof(nn->key));
    nn->fail_count = 1;
    nn->next = g_fail_limits; g_fail_limits = nn;
    pthread_mutex_unlock(&g_mutex);
}

static void reset_fail_count(const char *key) {
    pthread_mutex_lock(&g_mutex);
    FailLimitNode *n = g_fail_limits;
    while (n) {
        if (strcmp(n->key, key) == 0) { n->fail_count = 0; n->lock_until = 0; break; }
        n = n->next;
    }
    pthread_mutex_unlock(&g_mutex);
}

/* ==================== 二维码会话管理 ==================== */
static QRCodeSession* find_qr_session(const char *qr_id) {
    for (int i = 0; i < g_qr_session_count; i++)
        if (strcmp(g_qr_sessions[i].qr_id, qr_id) == 0) return &g_qr_sessions[i];
    return NULL;
}

static QRCodeSession* create_qr_session(void) {
    pthread_mutex_lock(&g_mutex);
    if (g_qr_session_count >= MAX_QR_SESSIONS) {
        /* 清理过期会话 */
        time_t now = time(NULL);
        for (int i = 0; i < g_qr_session_count; i++) {
            if (g_qr_sessions[i].expires_at < now || g_qr_sessions[i].status == 2 || g_qr_sessions[i].status == -1) {
                /* 移除：将最后的移到当前位置 */
                g_qr_sessions[i] = g_qr_sessions[g_qr_session_count - 1];
                g_qr_session_count--;
                i--;
            }
        }
        if (g_qr_session_count >= MAX_QR_SESSIONS) { pthread_mutex_unlock(&g_mutex); return NULL; }
    }
    QRCodeSession qr;
    memset(&qr, 0, sizeof(qr));
    generate_uuid(qr.qr_id, sizeof(qr.qr_id));
    qr.status = 0;
    qr.created_at = time(NULL);
    qr.expires_at = qr.created_at + g_config.qr_expire_seconds;

    QRCodeSession *new_sessions = realloc(g_qr_sessions, (g_qr_session_count + 1) * sizeof(QRCodeSession));
    if (!new_sessions) { pthread_mutex_unlock(&g_mutex); return NULL; }
    g_qr_sessions = new_sessions;
    g_qr_sessions[g_qr_session_count] = qr;
    QRCodeSession *ret = &g_qr_sessions[g_qr_session_count];
    g_qr_session_count++;
    pthread_mutex_unlock(&g_mutex);
    return ret;
}

/* ==================== IP 速率限制（密码登录） ==================== */
static void load_rate_limits(void) { /* 保持兼容 */ }
static void save_rate_limits(void) { /* 保持兼容 */ }

static RateLimitEntry* get_rate_limit(const char *ip) {
    for (int i = 0; i < g_rate_limit_count; i++)
        if (strcmp(g_rate_limits[i].ip, ip) == 0) return &g_rate_limits[i];

    RateLimitEntry *new_limits = realloc(g_rate_limits, (g_rate_limit_count + 1) * sizeof(RateLimitEntry));
    if (!new_limits) return NULL;  /* OOM：让调用方处理 */
    g_rate_limits = new_limits;
    memset(&g_rate_limits[g_rate_limit_count], 0, sizeof(RateLimitEntry));
    safe_strcpy(g_rate_limits[g_rate_limit_count].ip, ip, sizeof(g_rate_limits[0].ip));
    return &g_rate_limits[g_rate_limit_count++];
}

static int check_rate_limit(const char *ip) {
    RateLimitEntry *e = get_rate_limit(ip);
    if (!e) return -1;  /* OOM */
    time_t now = time(NULL);

    /* 锁定期已过：重置计数 */
    if (e->lockout_until > 0 && e->lockout_until <= now) {
        e->attempts = 0;
        e->lockout_until = 0;
    }

    /* 仍在锁定期内 */
    if (e->lockout_until > now) return -1;

    /* 正常：允许尝试 */
    return 0;
}
static void record_failed_login(const char *ip) {
    RateLimitEntry *e = get_rate_limit(ip);
    if (!e) return;  /* OOM */
    time_t now = time(NULL);
    e->attempts++; e->last_attempt = now;
    if (e->attempts >= MAX_LOGIN_ATTEMPTS) e->lockout_until = now + LOCKOUT_DURATION;
}
static void record_success_login(const char *ip) {
    RateLimitEntry *e = get_rate_limit(ip);
    if (!e) return;  /* OOM */
    e->attempts = 0; e->lockout_until = 0;
}

/* ==================== Token 管理 ==================== */
static char* generate_token(const char *username, int user_id, const char *role) {
    static char token[MAX_TOKEN_SIZE];
    unsigned char hash[32]; time_t now = time(NULL); time_t expire = now + TOKEN_EXPIRE_SEC;
    char salt[33]; generate_random_hex(salt, 32);
    char data[1024];
    snprintf(data, sizeof(data), "%s|%d|%s|%ld|%ld|%s", username, user_id, role, now, expire, salt);
    hmac_sha256(hash, TOKEN_SECRET, data);
    char sig[65]; for (int i = 0; i < 32; i++) sprintf(sig + i * 2, "%02x", hash[i]);
    snprintf(token, sizeof(token), "%ld.%ld.%d.%s.%s.%s", now, expire, user_id, role, salt, sig);
    return token;
}

/* ==================== HTTP 响应辅助 ==================== */
static int send_json(struct MHD_Connection *conn, int status_code, cJSON *obj) {
    char *str = cJSON_Print(obj);
    cJSON_Delete(obj);
    if (!str) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, resp);
        MHD_destroy_response(resp);
        return ret;
    }
    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(str), (void*)str, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    int ret = MHD_queue_response(conn, status_code, resp);
    MHD_destroy_response(resp);
    return ret;
}

static int send_error(struct MHD_Connection *conn, int status_code, const char *msg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddBoolToObject(obj, "success", 0);
    cJSON_AddStringToObject(obj, "msg", msg);
    cJSON_AddNumberToObject(obj, "code", status_code);
    return send_json(conn, status_code, obj);
}

/* ==================== 路由处理器 ==================== */

/* GET /api/auth_policy */
/* 每次请求时重新读取策略（确保策略变更实时生效） */
static void reload_policy(void) {
    FILE *fp = fopen(AUTH_CONFIG_FILE, "r");
    if (!fp) return;
    fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
    if (sz <= 0) { fclose(fp); return; }
    char *buf = malloc(sz + 1);
    if (!buf) { fclose(fp); return; }
    fread(buf, 1, sz, fp); buf[sz] = '\0'; fclose(fp);
    cJSON *root = cJSON_Parse(buf); free(buf);
    if (!root) return;

    cJSON *lp = cJSON_GetObjectItem(root, "login_policy");
    if (lp && cJSON_IsString(lp)) safe_strcpy(g_policy.login_policy, lp->valuestring, sizeof(g_policy.login_policy));

    cJSON *pp = cJSON_GetObjectItem(root, "password_policy");
    if (pp) {
        cJSON *v;
        v = cJSON_GetObjectItem(pp, "min_length"); if (v) g_policy.pw_min_length = (int)v->valuedouble;
        v = cJSON_GetObjectItem(pp, "require_uppercase"); if (v) g_policy.pw_require_uppercase = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp, "require_lowercase"); if (v) g_policy.pw_require_lowercase = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp, "require_digit"); if (v) g_policy.pw_require_digit = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp, "require_special"); if (v) g_policy.pw_require_special = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp, "forbid_username"); if (v) g_policy.pw_forbid_username = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp, "forbid_common"); if (v) g_policy.pw_forbid_common = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp, "history_count"); if (v) g_policy.pw_history_count = (int)v->valuedouble;
    }
    cJSON_Delete(root);
}

static int handle_auth_policy(struct MHD_Connection *conn) {
    /* 每次请求重新读策略文件，保证修改后立即生效 */
    reload_policy();

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "policy", g_policy.login_policy);
    cJSON_AddItemToObject(resp, "available_channels", build_available_channels());
    cJSON_AddItemToObject(resp, "available_methods", build_available_methods());

    cJSON *pp = cJSON_CreateObject();
    cJSON_AddNumberToObject(pp, "min_length", g_policy.pw_min_length);
    cJSON_AddBoolToObject(pp, "require_uppercase", g_policy.pw_require_uppercase);
    cJSON_AddBoolToObject(pp, "require_lowercase", g_policy.pw_require_lowercase);
    cJSON_AddBoolToObject(pp, "require_digit", g_policy.pw_require_digit);
    cJSON_AddBoolToObject(pp, "require_special", g_policy.pw_require_special);
    cJSON_AddBoolToObject(pp, "forbid_username", g_policy.pw_forbid_username);
    cJSON_AddBoolToObject(pp, "forbid_common", g_policy.pw_forbid_common);
    cJSON_AddBoolToObject(pp, "history_count", g_policy.pw_history_count);
    cJSON_AddItemToObject(resp, "password_policy", pp);

    /* 菜单 */
    if (g_module_menu) {
        cJSON *menu = cJSON_GetObjectItem(g_module_menu, "menu");
        if (menu) cJSON_AddItemToObject(resp, "menu", cJSON_Duplicate(menu, 1));
    }

    return send_json(conn, MHD_HTTP_OK, resp);
}

/* POST /api/send_sms_code */
static int handle_send_sms_code(struct MHD_Connection *conn, cJSON *req) {
    if (!g_sms_loaded) return send_error(conn, MHD_HTTP_SERVICE_UNAVAILABLE, "短信服务未启用");

    cJSON *user_obj = cJSON_GetObjectItem(req, "username");
    if (!user_obj || !cJSON_IsString(user_obj))
        return send_error(conn, MHD_HTTP_BAD_REQUEST, "缺少username参数");

    const char *username = user_obj->valuestring;
    cJSON *admin = find_admin_by_username(username);
    if (!admin) return send_error(conn, MHD_HTTP_NOT_FOUND, "用户不存在");

    cJSON *phone_obj = cJSON_GetObjectItem(admin, "phone");
    if (!phone_obj || !cJSON_IsString(phone_obj) || strlen(phone_obj->valuestring) == 0) {
        cJSON_Delete(admin);
        return send_error(conn, MHD_HTTP_BAD_REQUEST, "该用户未绑定手机号");
    }
    /* 复制 phone 字符串，避免 cJSON_Delete(admin) 后 use-after-free */
    char phone[MAX_PHONE_LEN];
    safe_strcpy(phone, phone_obj->valuestring, sizeof(phone));

    /* 检查限流（key: sms:phone） */
    char limit_key[128]; snprintf(limit_key, sizeof(limit_key), "sms:%s", phone);
    int lc = check_send_limit(limit_key, &g_config.sms_limit);
    if (lc == -1) { cJSON_Delete(admin); return send_error(conn, MHD_HTTP_TOO_MANY_REQUESTS, "发送过于频繁，请稍后再试"); }
    if (lc == -2) { cJSON_Delete(admin); return send_error(conn, MHD_HTTP_TOO_MANY_REQUESTS, "今日发送次数已达上限"); }

    cJSON_Delete(admin);

    /* 生成验证码 */
    char code[MAX_CODE_LEN];
    for (int i = 0; i < g_config.code_length; i++) {
        unsigned char b;
        if (RAND_bytes(&b, 1) != 1) { code[i] = '0'; continue; }
        code[i] = '0' + (b % 10);
    }
    code[g_config.code_length] = '\0';

    record_send_attempt(limit_key);

    int ret = sms_send_code(phone, code);
    if (ret != 0) {
        size_t pl = strlen(phone);
        LOG_ERROR("SMS 发送失败 phone=***%s ret=%d",
                  pl > 4 ? phone + pl - 4 : phone, ret);
        return send_error(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "短信发送失败，请稍后重试");
    }

    /* 存储验证码 */
    char code_key[128]; snprintf(code_key, sizeof(code_key), "sms:%s", phone);
    store_code(code_key, code);

    size_t pl = strlen(phone);
    LOG_INFO("SMS 验证码已发送 phone=***%s", pl > 4 ? phone + pl - 4 : phone);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddStringToObject(resp, "msg", "验证码已发送");
    return send_json(conn, MHD_HTTP_OK, resp);
}

/* POST /api/send_email_code */
static int handle_send_email_code(struct MHD_Connection *conn, cJSON *req) {
    if (!g_email_loaded) return send_error(conn, MHD_HTTP_SERVICE_UNAVAILABLE, "邮件服务未启用");

    cJSON *user_obj = cJSON_GetObjectItem(req, "username");
    if (!user_obj || !cJSON_IsString(user_obj))
        return send_error(conn, MHD_HTTP_BAD_REQUEST, "缺少username参数");

    const char *username = user_obj->valuestring;
    cJSON *admin = find_admin_by_username(username);
    if (!admin) return send_error(conn, MHD_HTTP_NOT_FOUND, "用户不存在");

    cJSON *email_obj = cJSON_GetObjectItem(admin, "email");
    if (!email_obj || !cJSON_IsString(email_obj) || strlen(email_obj->valuestring) == 0) {
        cJSON_Delete(admin);
        return send_error(conn, MHD_HTTP_BAD_REQUEST, "该用户未绑定邮箱");
    }
    /* 复制 email 字符串，避免 cJSON_Delete(admin) 后 use-after-free */
    char email[MAX_EMAIL_LEN];
    safe_strcpy(email, email_obj->valuestring, sizeof(email));

    char limit_key[128]; snprintf(limit_key, sizeof(limit_key), "email:%s", email);
    int lc = check_send_limit(limit_key, &g_config.email_limit);
    if (lc == -1) { cJSON_Delete(admin); return send_error(conn, MHD_HTTP_TOO_MANY_REQUESTS, "发送过于频繁，请稍后再试"); }
    if (lc == -2) { cJSON_Delete(admin); return send_error(conn, MHD_HTTP_TOO_MANY_REQUESTS, "今日发送次数已达上限"); }

    cJSON_Delete(admin);

    char code[MAX_CODE_LEN];
    for (int i = 0; i < g_config.code_length; i++) {
        unsigned char b;
        if (RAND_bytes(&b, 1) != 1) { code[i] = '0'; continue; }
        code[i] = '0' + (b % 10);
    }
    code[g_config.code_length] = '\0';

    record_send_attempt(limit_key);

    int ret = email_send_code(email, username, code);
    if (ret != 0) {
        LOG_ERROR("EMAIL 发送失败 email=%s ret=%d", email, ret);
        return send_error(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "邮件发送失败，请稍后重试");
    }

    char code_key[128]; snprintf(code_key, sizeof(code_key), "email:%s", email);
    store_code(code_key, code);

    LOG_INFO("EMAIL 验证码已发送 email=%s", email);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddStringToObject(resp, "msg", "验证码已发送");
    return send_json(conn, MHD_HTTP_OK, resp);
}

/* POST /api/qrcode/create */
static int handle_qrcode_create(struct MHD_Connection *conn) {
    if (!is_channel_in_policy(g_policy.login_policy, "qrcode"))
        return send_error(conn, MHD_HTTP_FORBIDDEN, "二维码登录未在策略中启用");

    QRCodeSession *qr = create_qr_session();
    if (!qr) return send_error(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "二维码会话已满");

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddStringToObject(resp, "qr_id", qr->qr_id);
    cJSON_AddStringToObject(resp, "qr_content", qr->qr_id);
    return send_json(conn, MHD_HTTP_OK, resp);
}

/* GET /api/qrcode/status */
static int handle_qrcode_status(struct MHD_Connection *conn, const char *query) {
    /* 解析 qr_id */
    const char *key = "qr_id=";
    const char *p = query ? strstr(query, key) : NULL;
    if (!p) return send_error(conn, MHD_HTTP_BAD_REQUEST, "缺少qr_id参数");
    const char *qr_id = p + strlen(key);
    char id[MAX_UUID_LEN]; safe_strcpy(id, qr_id, sizeof(id));
    /* 去除尾部额外参数 */
    char *amp = strchr(id, '&'); if (amp) *amp = '\0';

    pthread_mutex_lock(&g_mutex);
    QRCodeSession *qr = find_qr_session(id);
    if (!qr) { pthread_mutex_unlock(&g_mutex); return send_error(conn, MHD_HTTP_NOT_FOUND, "二维码不存在或已过期"); }

    time_t now = time(NULL);
    if (now > qr->expires_at) {
        qr->status = -1;
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddNumberToObject(resp, "status", -1);
        cJSON_AddStringToObject(resp, "msg", "二维码已过期");
        pthread_mutex_unlock(&g_mutex);
        return send_json(conn, MHD_HTTP_OK, resp);
    }

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddNumberToObject(resp, "status", qr->status);
    if (qr->status == 0) cJSON_AddStringToObject(resp, "msg", "待扫描");
    else if (qr->status == 1) cJSON_AddStringToObject(resp, "msg", "已扫码，请在App确认");
    else if (qr->status == 2) {
        cJSON_AddStringToObject(resp, "msg", "登录成功");
        cJSON_AddStringToObject(resp, "token", qr->token);
    }
    pthread_mutex_unlock(&g_mutex);
    return send_json(conn, MHD_HTTP_OK, resp);
}

/* POST /api/qrcode/confirm */
static int handle_qrcode_confirm(struct MHD_Connection *conn, cJSON *req) {
    cJSON *qr_obj = cJSON_GetObjectItem(req, "qr_id");
    cJSON *token_obj = cJSON_GetObjectItem(req, "app_token");
    if (!qr_obj || !cJSON_IsString(qr_obj))
        return send_error(conn, MHD_HTTP_BAD_REQUEST, "缺少qr_id");

    const char *qr_id = qr_obj->valuestring;
    pthread_mutex_lock(&g_mutex);
    QRCodeSession *qr = find_qr_session(qr_id);
    if (!qr) { pthread_mutex_unlock(&g_mutex); return send_error(conn, MHD_HTTP_NOT_FOUND, "二维码不存在或已过期"); }
    if (time(NULL) > qr->expires_at) { qr->status = -1; pthread_mutex_unlock(&g_mutex); return send_error(conn, MHD_HTTP_GONE, "二维码已过期"); }

    if (qr->status == 0) {
        /* 扫码操作：状态变为"待确认" */
        qr->status = 1;
        if (token_obj && cJSON_IsString(token_obj)) {
            /* TODO: 验证App Token，从Token中提取username */
            /* 简化实现：后续由 auth.c:verify_token 处理 */
        }
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddBoolToObject(resp, "success", 1);
        cJSON_AddStringToObject(resp, "msg", "已扫码，请在App确认");
        pthread_mutex_unlock(&g_mutex);
        return send_json(conn, MHD_HTTP_OK, resp);
    } else if (qr->status == 1) {
        /* 确认操作 */
        /* 实际应用中应由已验证的App Token确定username，此处简化 */
        char username[64] = "scanned_user";
        if (token_obj && cJSON_IsString(token_obj)) {
            /* 从App Token解码用户名 */
            /* TODO: verify app token */
        }
        safe_strcpy(qr->username, username, sizeof(qr->username));
        qr->status = 2;
        /* 生成登录Token */
        cJSON *admin = find_admin_by_username(username);
        if (admin) {
            cJSON *role_obj = cJSON_GetObjectItem(admin, "role");
            cJSON *id_obj = cJSON_GetObjectItem(admin, "id");
            char role[32] = "operator"; int uid = 0;
            if (role_obj) safe_strcpy(role, role_obj->valuestring, sizeof(role));
            if (id_obj) uid = (int)id_obj->valuedouble;
            char *tok = generate_token(username, uid, role);
            safe_strcpy(qr->token, tok, sizeof(qr->token));
            cJSON_Delete(admin);
        }
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddBoolToObject(resp, "success", 1);
        cJSON_AddStringToObject(resp, "msg", "登录成功");
        pthread_mutex_unlock(&g_mutex);
        return send_json(conn, MHD_HTTP_OK, resp);
    }

    pthread_mutex_unlock(&g_mutex);
    return send_error(conn, MHD_HTTP_BAD_REQUEST, "无效的二维码状态");
}

/* POST /api/login - 统一登录入口 */
static int handle_login(struct MHD_Connection *conn, cJSON *req, const char *client_ip) {
    cJSON *type_obj = cJSON_GetObjectItem(req, "login_type");
    const char *login_type = (type_obj && cJSON_IsString(type_obj)) ? type_obj->valuestring : "password";
    LOG_INFO("收到登录请求: type=%s ip=%s", login_type, client_ip);
    /* 重新加载策略，确保最新配置生效 */
    reload_policy();
    cJSON *user_obj = cJSON_GetObjectItem(req, "username");
    const char *username = (user_obj && cJSON_IsString(user_obj)) ? user_obj->valuestring : NULL;

    if (!username) return send_error(conn, MHD_HTTP_BAD_REQUEST, "缺少username参数");

    /* 检查策略是否允许该登录方式 */
    int is_dual = is_dual_factor_policy();

    if (strcmp(login_type, "password") == 0) {
        /* ===== 密码登录 ===== */
        if (!is_channel_in_policy(g_policy.login_policy, "password"))
            return send_error(conn, MHD_HTTP_FORBIDDEN, "密码登录未在策略中启用");

        if (check_rate_limit(client_ip) < 0)
            return send_error(conn, MHD_HTTP_TOO_MANY_REQUESTS, "登录尝试次数过多，请5分钟后再试");

        cJSON *pw_obj = cJSON_GetObjectItem(req, "password");
        if (!pw_obj || !cJSON_IsString(pw_obj)) {
            record_failed_login(client_ip);
            return send_error(conn, MHD_HTTP_BAD_REQUEST, "缺少password参数");
        }

        cJSON *admin = find_admin_by_username(username);
        if (!admin) { record_failed_login(client_ip); return send_error(conn, MHD_HTTP_UNAUTHORIZED, "用户名或密码错误"); }
        cJSON *stored_pw = cJSON_GetObjectItem(admin, "password");
        if (!stored_pw || !verify_password(pw_obj->valuestring, stored_pw->valuestring)) {
            record_failed_login(client_ip); write_audit_log(username, "login:password", client_ip, 0); cJSON_Delete(admin);
            return send_error(conn, MHD_HTTP_UNAUTHORIZED, "用户名或密码错误");
        }

        /* 双因子策略：仅在策略中不存在 password_only 时强制要求第二因子 */
        if (is_dual && !strstr(g_policy.login_policy, "password_only")) {
            const char *dual_ch = get_dual_channel();
            cJSON_Delete(admin);
            record_success_login(client_ip);
            cJSON *resp = cJSON_CreateObject();
            cJSON_AddBoolToObject(resp, "success", 1);
            cJSON_AddNumberToObject(resp, "step", 2);
            cJSON_AddBoolToObject(resp, "need_code", 1);
            cJSON_AddStringToObject(resp, "channel", dual_ch);
            cJSON_AddStringToObject(resp, "msg", "验证码已发送");
            return send_json(conn, MHD_HTTP_OK, resp);
        }

        /* 单因子：直接生成Token */
        cJSON *role_obj = cJSON_GetObjectItem(admin, "role");
        cJSON *id_obj = cJSON_GetObjectItem(admin, "id");
        char role[32] = "operator"; int uid = 0;
        if (role_obj) safe_strcpy(role, role_obj->valuestring, sizeof(role));
        if (id_obj) uid = (int)id_obj->valuedouble;
        cJSON_Delete(admin);

        record_success_login(client_ip);
        write_audit_log(username, "login:password", client_ip, 1);
        char *tok = generate_token(username, uid, role);
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddBoolToObject(resp, "success", 1);
        cJSON_AddStringToObject(resp, "token", tok);
        cJSON_AddStringToObject(resp, "username", username);
        cJSON_AddStringToObject(resp, "role", role);
        return send_json(conn, MHD_HTTP_OK, resp);
    }
    else if (strcmp(login_type, "sms") == 0) {
        /* ===== 短信验证码登录（阿里云官方校验）===== */
        LOG_INFO("SMS登录: 开始 user=%s", username);
        if (!g_sms_loaded) {
            LOG_ERROR("SMS登录: 服务未加载");
            return send_error(conn, MHD_HTTP_SERVICE_UNAVAILABLE, "短信服务未启用");
        }
        if (!is_channel_in_policy(g_policy.login_policy, "sms")) {
            LOG_ERROR("SMS登录: 策略未启用 policy=%s", g_policy.login_policy);
            return send_error(conn, MHD_HTTP_FORBIDDEN, "短信登录未在策略中启用");
        }

        cJSON *code_obj = cJSON_GetObjectItem(req, "code");
        if (!code_obj || !cJSON_IsString(code_obj)) {
            LOG_ERROR("SMS登录: 缺少验证码");
            return send_error(conn, MHD_HTTP_BAD_REQUEST, "缺少验证码");
        }
        LOG_INFO("SMS登录: code=%s", code_obj->valuestring);

        cJSON *admin = find_admin_by_username(username);
        if (!admin) {
            LOG_ERROR("SMS登录: 用户不存在 user=%s", username);
            return send_error(conn, MHD_HTTP_UNAUTHORIZED, "用户不存在或未绑定");
        }

        cJSON *phone_obj = cJSON_GetObjectItem(admin, "phone");
        if (!phone_obj || !cJSON_IsString(phone_obj) || strlen(phone_obj->valuestring) == 0) {
            LOG_ERROR("SMS登录: 未绑定手机号 user=%s", username);
            cJSON_Delete(admin);
            return send_error(conn, MHD_HTTP_BAD_REQUEST, "该用户未绑定手机号");
        }
        char phone[128]; safe_strcpy(phone, phone_obj->valuestring, sizeof(phone));
        cJSON_Delete(admin);

        /* 失败限流 */
        char fail_key[128]; snprintf(fail_key, sizeof(fail_key), "fail:%s", username);
        if (check_fail_lock(fail_key, &g_config.sms_limit) != 0) {
            LOG_ERROR("SMS登录: 失败锁定 user=%s", username);
            return send_error(conn, MHD_HTTP_TOO_MANY_REQUESTS, "验证码尝试次数过多，请稍后再试");
        }

        /* 调用阿里云官方校验 */
        LOG_INFO("SMS登录: 校验中 phone=%s code=%s", phone, code_obj->valuestring);
        int vret = sms_verify_code(phone, code_obj->valuestring);
        LOG_INFO("SMS登录: 校验结果 vret=%d", vret);
        if (vret != 0) {
            LOG_ERROR("SMS登录: 校验失败 vret=%d phone=%s code=%s", vret, phone, code_obj->valuestring);
            record_fail_attempt(fail_key, &g_config.sms_limit);
            char err_detail[256];
            snprintf(err_detail, sizeof(err_detail), "验证码无效或已过期 (ret=%d)", vret);
            return send_error(conn, MHD_HTTP_UNAUTHORIZED, err_detail);
        }
        LOG_INFO("SMS登录: 校验通过!");

        reset_fail_count(fail_key);
        LOG_INFO("SMS登录: 生成Token...");

        /* 生成Token */
        cJSON *admin2 = find_admin_by_field("phone", phone);
        if (!admin2) {
            LOG_ERROR("SMS登录: find_admin_by_field fail phone=%s", phone);
            return send_error(conn, MHD_HTTP_UNAUTHORIZED, "用户数据异常");
        }

        cJSON *role_obj = cJSON_GetObjectItem(admin2, "role");
        cJSON *id_obj = cJSON_GetObjectItem(admin2, "id");
        char role[32] = "operator"; int uid = 0;
        if (role_obj) safe_strcpy(role, role_obj->valuestring, sizeof(role));
        if (id_obj) uid = (int)id_obj->valuedouble;
        char *uname2 = NULL;
        cJSON *uobj = cJSON_GetObjectItem(admin2, "username");
        if (uobj) uname2 = uobj->valuestring;
        char uid_username[64]; safe_strcpy(uid_username, uname2 ? uname2 : username, sizeof(uid_username));
        cJSON_Delete(admin2);

        LOG_INFO("SMS登录: 成功! user=%s role=%s uid=%d", uid_username, role, uid);
        write_audit_log(uid_username, "login:sms", client_ip, 1);
        char *tok = generate_token(uid_username, uid, role);
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddBoolToObject(resp, "success", 1);
        cJSON_AddStringToObject(resp, "token", tok);
        cJSON_AddStringToObject(resp, "username", uid_username);
        cJSON_AddStringToObject(resp, "role", role);
        return send_json(conn, MHD_HTTP_OK, resp);
    }
    else if (strcmp(login_type, "email") == 0) {
        /* ===== 邮件验证码登录（本地校验）===== */
        if (!g_email_loaded)
            return send_error(conn, MHD_HTTP_SERVICE_UNAVAILABLE, "邮件服务未启用");
        if (!is_channel_in_policy(g_policy.login_policy, "email"))
            return send_error(conn, MHD_HTTP_FORBIDDEN, "邮件登录未在策略中启用");

        cJSON *code_obj = cJSON_GetObjectItem(req, "code");
        if (!code_obj || !cJSON_IsString(code_obj))
            return send_error(conn, MHD_HTTP_BAD_REQUEST, "缺少验证码");

        cJSON *admin = find_admin_by_username(username);
        if (!admin) return send_error(conn, MHD_HTTP_UNAUTHORIZED, "用户不存在或未绑定");

        cJSON *email_obj = cJSON_GetObjectItem(admin, "email");
        if (!email_obj || !cJSON_IsString(email_obj) || strlen(email_obj->valuestring) == 0) {
            cJSON_Delete(admin);
            return send_error(conn, MHD_HTTP_BAD_REQUEST, "该用户未绑定邮箱");
        }
        char email_addr[128]; safe_strcpy(email_addr, email_obj->valuestring, sizeof(email_addr));
        cJSON_Delete(admin);

        /* 失败限流 */
        char fail_key[128]; snprintf(fail_key, sizeof(fail_key), "fail:%s", username);
        if (check_fail_lock(fail_key, &g_config.email_limit) != 0)
            return send_error(conn, MHD_HTTP_TOO_MANY_REQUESTS, "验证码尝试次数过多，请稍后再试");

        /* 本地校验 */
        char code_key[128]; snprintf(code_key, sizeof(code_key), "email:%s", email_addr);
        if (!verify_and_consume_code(code_key, code_obj->valuestring)) {
            record_fail_attempt(fail_key, &g_config.email_limit);
            return send_error(conn, MHD_HTTP_UNAUTHORIZED, "验证码无效或已过期");
        }

        reset_fail_count(fail_key);

        /* 生成Token */
        cJSON *admin2 = find_admin_by_field("email", email_addr);
        if (!admin2) return send_error(conn, MHD_HTTP_UNAUTHORIZED, "用户数据异常");

        cJSON *role_obj = cJSON_GetObjectItem(admin2, "role");
        cJSON *id_obj = cJSON_GetObjectItem(admin2, "id");
        char role[32] = "operator"; int uid = 0;
        if (role_obj) safe_strcpy(role, role_obj->valuestring, sizeof(role));
        if (id_obj) uid = (int)id_obj->valuedouble;
        char *uname2 = NULL;
        cJSON *uobj = cJSON_GetObjectItem(admin2, "username");
        if (uobj) uname2 = uobj->valuestring;
        char uid_username[64]; safe_strcpy(uid_username, uname2 ? uname2 : username, sizeof(uid_username));
        cJSON_Delete(admin2);

        write_audit_log(uid_username, "login:email", client_ip, 1);
        char *tok = generate_token(uid_username, uid, role);
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddBoolToObject(resp, "success", 1);
        cJSON_AddStringToObject(resp, "token", tok);
        cJSON_AddStringToObject(resp, "username", uid_username);
        cJSON_AddStringToObject(resp, "role", role);
        return send_json(conn, MHD_HTTP_OK, resp);
    }
    else if (strcmp(login_type, "totp") == 0) {
        /* ===== TOTP 登录 ===== */
        LOG_INFO("TOTP登录: 开始 user=%s", username);
        if (!g_totp_loaded) {
            LOG_ERROR("TOTP登录: 模块未加载");
            return send_error(conn, MHD_HTTP_SERVICE_UNAVAILABLE, "TOTP通道不可用");
        }
        if (!is_channel_in_policy(g_policy.login_policy, "totp")) {
            LOG_ERROR("TOTP登录: 策略未启用 policy=%s", g_policy.login_policy);
            return send_error(conn, MHD_HTTP_FORBIDDEN, "TOTP登录未在策略中启用");
        }

        cJSON *code_obj = cJSON_GetObjectItem(req, "code");
        if (!code_obj || !cJSON_IsString(code_obj)) {
            LOG_ERROR("TOTP登录: 缺少动态码");
            return send_error(conn, MHD_HTTP_BAD_REQUEST, "缺少TOTP动态码");
        }
        LOG_INFO("TOTP登录: code=%s", code_obj->valuestring);

        cJSON *admin = find_admin_by_username(username);
        if (!admin) {
            LOG_ERROR("TOTP登录: 用户不存在 user=%s", username);
            return send_error(conn, MHD_HTTP_UNAUTHORIZED, "用户不存在");
        }

        cJSON *secret_obj = cJSON_GetObjectItem(admin, "totp_secret");
        cJSON *enabled_obj = cJSON_GetObjectItem(admin, "totp_enabled");
        if (!secret_obj || !cJSON_IsString(secret_obj) || strlen(secret_obj->valuestring) == 0 ||
            !enabled_obj || !cJSON_IsTrue(enabled_obj)) {
            LOG_ERROR("TOTP登录: 未启用 user=%s has_secret=%d enabled=%d",
                      username, secret_obj ? 1 : 0, enabled_obj ? cJSON_IsTrue(enabled_obj) : 0);
            cJSON_Delete(admin);
            return send_error(conn, MHD_HTTP_BAD_REQUEST, "该用户未启用TOTP");
        }
        LOG_INFO("TOTP登录: 密钥=%c%c%c...%c", secret_obj->valuestring[0], secret_obj->valuestring[1],
                 secret_obj->valuestring[2], secret_obj->valuestring[strlen(secret_obj->valuestring)-1]);

        char fail_key[128]; snprintf(fail_key, sizeof(fail_key), "fail:%s", username);
        if (check_fail_lock(fail_key, &g_config.totp_limit) != 0) {
            LOG_ERROR("TOTP登录: 失败锁定 user=%s", username);
            cJSON_Delete(admin);
            return send_error(conn, MHD_HTTP_TOO_MANY_REQUESTS, "TOTP尝试次数过多，请稍后再试");
        }

        LOG_INFO("TOTP登录: 校验中...");
        int vret = totp_verify(secret_obj->valuestring, code_obj->valuestring);
        LOG_INFO("TOTP登录: 校验结果 vret=%d", vret);
        if (vret != 0) {
            LOG_ERROR("TOTP登录: 校验失败 vret=%d user=%s", vret, username);
            record_fail_attempt(fail_key, &g_config.totp_limit);
            cJSON_Delete(admin);
            return send_error(conn, MHD_HTTP_UNAUTHORIZED, "TOTP动态码无效");
        }

        LOG_INFO("TOTP登录: 校验通过!");
        reset_fail_count(fail_key);
        cJSON *role_obj = cJSON_GetObjectItem(admin, "role");
        cJSON *id_obj = cJSON_GetObjectItem(admin, "id");
        char role[32] = "operator"; int uid = 0;
        if (role_obj) safe_strcpy(role, role_obj->valuestring, sizeof(role));
        if (id_obj) uid = (int)id_obj->valuedouble;
        cJSON_Delete(admin);

        LOG_INFO("TOTP登录: 成功 user=%s role=%s uid=%d", username, role, uid);
        char *tok = generate_token(username, uid, role);
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddBoolToObject(resp, "success", 1);
        cJSON_AddStringToObject(resp, "token", tok);
        cJSON_AddStringToObject(resp, "username", username);
        cJSON_AddStringToObject(resp, "role", role);
        return send_json(conn, MHD_HTTP_OK, resp);
    }
    else if (strcmp(login_type, "cert") == 0) {
        /* ===== 客户端证书登录 ===== */
        if (!g_cert_loaded) return send_error(conn, MHD_HTTP_SERVICE_UNAVAILABLE, "证书通道不可用");
        if (!is_channel_in_policy(g_policy.login_policy, "cert"))
            return send_error(conn, MHD_HTTP_FORBIDDEN, "证书登录未在策略中启用");

        cJSON *fp_obj = cJSON_GetObjectItem(req, "fingerprint");
        if (!fp_obj || !cJSON_IsString(fp_obj))
            return send_error(conn, MHD_HTTP_BAD_REQUEST, "缺少证书指纹");

        cJSON *admin = find_admin_by_username(username);
        if (!admin) return send_error(conn, MHD_HTTP_UNAUTHORIZED, "用户不存在");

        cJSON *stored_fp = cJSON_GetObjectItem(admin, "cert_fingerprint");
        if (!stored_fp || !cJSON_IsString(stored_fp) || strlen(stored_fp->valuestring) == 0) {
            cJSON_Delete(admin);
            return send_error(conn, MHD_HTTP_BAD_REQUEST, "该用户未绑定客户端证书");
        }

        int vret = cert_verify(stored_fp->valuestring, fp_obj->valuestring);
        if (vret != 0) { cJSON_Delete(admin); return send_error(conn, MHD_HTTP_UNAUTHORIZED, "证书指纹不匹配"); }

        cJSON *role_obj = cJSON_GetObjectItem(admin, "role");
        cJSON *id_obj = cJSON_GetObjectItem(admin, "id");
        char role[32] = "operator"; int uid = 0;
        if (role_obj) safe_strcpy(role, role_obj->valuestring, sizeof(role));
        if (id_obj) uid = (int)id_obj->valuedouble;
        cJSON_Delete(admin);

        char *tok = generate_token(username, uid, role);
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddBoolToObject(resp, "success", 1);
        cJSON_AddStringToObject(resp, "token", tok);
        cJSON_AddStringToObject(resp, "username", username);
        cJSON_AddStringToObject(resp, "role", role);
        return send_json(conn, MHD_HTTP_OK, resp);
    }
    else if (strcmp(login_type, "dual") == 0) {
        /* ===== 双因子登录（第二步或组合表单一次性提交）===== */
        if (!is_dual) return send_error(conn, MHD_HTTP_BAD_REQUEST, "当前非双因子策略");
        /* 优先从请求读取 dual_channel，回退到策略 */
        const char *dual_ch = get_dual_channel();
        cJSON *req_dual = cJSON_GetObjectItem(req, "dual_channel");
        if (req_dual && cJSON_IsString(req_dual))
            dual_ch = req_dual->valuestring;
        LOG_INFO("双因子登录: channel=%s user=%s", dual_ch, username);

        cJSON *code_obj = cJSON_GetObjectItem(req, "code");
        if (!code_obj || !cJSON_IsString(code_obj))
            return send_error(conn, MHD_HTTP_BAD_REQUEST, "缺少验证码");

        cJSON *admin = find_admin_by_username(username);
        if (!admin) return send_error(conn, MHD_HTTP_UNAUTHORIZED, "用户不存在");

        /* 根据双因子通道校验 */
        if (strcmp(dual_ch, "sms") == 0) {
            if (!g_sms_loaded) { cJSON_Delete(admin); return send_error(conn, MHD_HTTP_SERVICE_UNAVAILABLE, "短信通道不可用"); }
            cJSON *phone_obj = cJSON_GetObjectItem(admin, "phone");
            if (!phone_obj || !cJSON_IsString(phone_obj) || strlen(phone_obj->valuestring) == 0) {
                cJSON_Delete(admin); return send_error(conn, MHD_HTTP_BAD_REQUEST, "未绑定手机号");
            }
            char phone[128]; safe_strcpy(phone, phone_obj->valuestring, sizeof(phone));
            cJSON_Delete(admin);

            char fail_key[128]; snprintf(fail_key, sizeof(fail_key), "fail:%s", username);
            if (check_fail_lock(fail_key, &g_config.sms_limit) != 0)
                return send_error(conn, MHD_HTTP_TOO_MANY_REQUESTS, "验证码尝试次数过多");

            int vret = sms_verify_code(phone, code_obj->valuestring);
            if (vret != 0) {
                record_fail_attempt(fail_key, &g_config.sms_limit);
                return send_error(conn, MHD_HTTP_UNAUTHORIZED, "验证码无效或已过期");
            }
            reset_fail_count(fail_key);
        } else if (strcmp(dual_ch, "email") == 0) {
            if (!g_email_loaded) { cJSON_Delete(admin); return send_error(conn, MHD_HTTP_SERVICE_UNAVAILABLE, "邮件通道不可用"); }
            cJSON *email_obj = cJSON_GetObjectItem(admin, "email");
            if (!email_obj || !cJSON_IsString(email_obj) || strlen(email_obj->valuestring) == 0) {
                cJSON_Delete(admin); return send_error(conn, MHD_HTTP_BAD_REQUEST, "未绑定邮箱");
            }
            char email_addr[128]; safe_strcpy(email_addr, email_obj->valuestring, sizeof(email_addr));
            cJSON_Delete(admin);

            char fail_key[128]; snprintf(fail_key, sizeof(fail_key), "fail:%s", username);
            if (check_fail_lock(fail_key, &g_config.email_limit) != 0)
                return send_error(conn, MHD_HTTP_TOO_MANY_REQUESTS, "验证码尝试次数过多");

            char code_key[128]; snprintf(code_key, sizeof(code_key), "email:%s", email_addr);
            if (!verify_and_consume_code(code_key, code_obj->valuestring)) {
                record_fail_attempt(fail_key, &g_config.email_limit);
                return send_error(conn, MHD_HTTP_UNAUTHORIZED, "验证码无效或已过期");
            }
            reset_fail_count(fail_key);
        } else if (strcmp(dual_ch, "totp") == 0) {
            LOG_INFO("双因子TOTP: 校验中 user=%s", username);
            if (!g_totp_loaded) {
                LOG_ERROR("双因子TOTP: 模块未加载");
                cJSON_Delete(admin); return send_error(conn, MHD_HTTP_SERVICE_UNAVAILABLE, "TOTP不可用");
            }
            cJSON *secret_obj = cJSON_GetObjectItem(admin, "totp_secret");
            if (!secret_obj || !cJSON_IsString(secret_obj) || strlen(secret_obj->valuestring) == 0) {
                LOG_ERROR("双因子TOTP: 未启用 user=%s", username);
                cJSON_Delete(admin); return send_error(conn, MHD_HTTP_BAD_REQUEST, "未启用TOTP");
            }
            int vret = totp_verify(secret_obj->valuestring, code_obj->valuestring);
            LOG_INFO("双因子TOTP: 校验结果 vret=%d user=%s", vret, username);
            cJSON_Delete(admin);
            if (vret != 0) { LOG_ERROR("双因子TOTP: 校验失败 user=%s", username); return send_error(conn, MHD_HTTP_UNAUTHORIZED, "TOTP动态码无效"); }
            LOG_INFO("双因子TOTP: 校验通过! user=%s", username);
        } else if (strcmp(dual_ch, "cert") == 0) {
            if (!g_cert_loaded) { cJSON_Delete(admin); return send_error(conn, MHD_HTTP_SERVICE_UNAVAILABLE, "证书通道不可用"); }
            cJSON *stored_fp = cJSON_GetObjectItem(admin, "cert_fingerprint");
            if (!stored_fp || !cJSON_IsString(stored_fp) || strlen(stored_fp->valuestring) == 0) {
                cJSON_Delete(admin); return send_error(conn, MHD_HTTP_BAD_REQUEST, "未绑定证书");
            }
            int vret = cert_verify(stored_fp->valuestring, code_obj->valuestring);
            cJSON_Delete(admin);
            if (vret != 0) return send_error(conn, MHD_HTTP_UNAUTHORIZED, "证书指纹不匹配");
        } else {
            cJSON_Delete(admin);
            return send_error(conn, MHD_HTTP_BAD_REQUEST, "未知的验证通道");
        }

        /* 双因子全通过，生成Token */
        admin = find_admin_by_username(username);
        if (!admin) return send_error(conn, MHD_HTTP_UNAUTHORIZED, "用户数据异常");
        cJSON *role_obj = cJSON_GetObjectItem(admin, "role");
        cJSON *id_obj = cJSON_GetObjectItem(admin, "id");
        char role[32] = "operator"; int uid = 0;
        if (role_obj) safe_strcpy(role, role_obj->valuestring, sizeof(role));
        if (id_obj) uid = (int)id_obj->valuedouble;
        cJSON_Delete(admin);

        char *tok = generate_token(username, uid, role);
        cJSON *resp = cJSON_CreateObject();
        cJSON_AddBoolToObject(resp, "success", 1);
        cJSON_AddStringToObject(resp, "token", tok);
        cJSON_AddStringToObject(resp, "username", username);
        cJSON_AddStringToObject(resp, "role", role);
        return send_json(conn, MHD_HTTP_OK, resp);
    }
    else if (strcmp(login_type, "qrcode") == 0) {
        return send_error(conn, MHD_HTTP_BAD_REQUEST, "二维码登录请通过轮询 /api/qrcode/status 完成");
    }

    return send_error(conn, MHD_HTTP_BAD_REQUEST, "未知的登录方式");
}

/* ==================== HTTP 请求处理 ==================== */
struct ConnContext {
    char *data;
    size_t size;
    size_t cap;
    int done;
};

static void *init_conn_context(void) { return calloc(1, sizeof(struct ConnContext)); }
static void free_conn_context(void *ctx) {
    if (!ctx) return;
    struct ConnContext *c = ctx;
    free(c->data);
    free(c);
}

static enum MHD_Result ahc(void *cls, struct MHD_Connection *conn,
                          const char *url, const char *method,
                          const char *version, const char *upload_data,
                          size_t *upload_data_size, void **con_cls) {
    (void)cls; (void)version;

    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(resp, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        MHD_add_response_header(resp, "Access-Control-Allow-Headers", "Content-Type, Authorization");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    if (strncmp(url, "/api/", 5) != 0) {
        const char *page = "{\"service\":\"Auth API\",\"status\":\"running\"}";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(page), (void*)page, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    const char *path = url + 5;

    /* 提取客户端 IP */
    char client_ip[64] = "unknown";
    const union MHD_ConnectionInfo *info = MHD_get_connection_info(conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (info && info->client_addr) {
        if (info->client_addr->sa_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in*)info->client_addr;
            inet_ntop(AF_INET, &s->sin_addr, client_ip, sizeof(client_ip));
        }
    }

    /* GET 请求 */
    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "auth_policy") == 0)
            return handle_auth_policy(conn);
        else if (strncmp(path, "qrcode/status", 13) == 0) {
            const char *query = strchr(path, '?');
            return handle_qrcode_status(conn, query);
        }
        cJSON *err = cJSON_CreateObject();
        cJSON_AddBoolToObject(err, "success", 0);
        cJSON_AddStringToObject(err, "msg", "未知接口");
        return send_json(conn, MHD_HTTP_NOT_FOUND, err);
    }

    /* POST 请求 */
    if (strcmp(method, "POST") != 0)
        return send_error(conn, MHD_HTTP_METHOD_NOT_ALLOWED, "不支持的请求方法");

    struct ConnContext *ctx = *con_cls;
    if (!ctx) { ctx = init_conn_context(); *con_cls = ctx; }

    if (*upload_data_size > 0) {
        if (ctx->size + *upload_data_size + 1 > ctx->cap) {
            size_t new_cap = ctx->size + *upload_data_size + 1;
            if (new_cap > MAX_REQUEST_SIZE) { free_conn_context(ctx); *con_cls = NULL; return MHD_NO; }
            char *new_data = realloc(ctx->data, new_cap);
            if (!new_data) { free_conn_context(ctx); *con_cls = NULL; return MHD_NO; }
            ctx->data = new_data;
            ctx->cap = new_cap;
        }
        memcpy(ctx->data + ctx->size, upload_data, *upload_data_size);
        ctx->size += *upload_data_size;
        ctx->data[ctx->size] = '\0';
        *upload_data_size = 0;
        return MHD_YES;
    }

    if (ctx->size == 0 || ctx->done)
        return MHD_YES;

    ctx->done = 1;

    /* 路由分发 */
    if (strcmp(path, "login") == 0) {
        cJSON *req = cJSON_Parse(ctx->data);
        if (!req) return send_error(conn, MHD_HTTP_BAD_REQUEST, "无效的JSON格式");
        enum MHD_Result ret = handle_login(conn, req, client_ip);
        cJSON_Delete(req);
        return ret;
    }
    else if (strcmp(path, "send_sms_code") == 0) {
        cJSON *req = cJSON_Parse(ctx->data);
        if (!req) return send_error(conn, MHD_HTTP_BAD_REQUEST, "无效的JSON格式");
        enum MHD_Result ret = handle_send_sms_code(conn, req);
        cJSON_Delete(req);
        return ret;
    }
    else if (strcmp(path, "send_email_code") == 0) {
        cJSON *req = cJSON_Parse(ctx->data);
        if (!req) return send_error(conn, MHD_HTTP_BAD_REQUEST, "无效的JSON格式");
        enum MHD_Result ret = handle_send_email_code(conn, req);
        cJSON_Delete(req);
        return ret;
    }
    else if (strcmp(path, "qrcode/create") == 0) {
        return handle_qrcode_create(conn);
    }
    else if (strcmp(path, "qrcode/confirm") == 0) {
        cJSON *req = cJSON_Parse(ctx->data);
        if (!req) return send_error(conn, MHD_HTTP_BAD_REQUEST, "无效的JSON格式");
        enum MHD_Result ret = handle_qrcode_confirm(conn, req);
        cJSON_Delete(req);
        return ret;
    }

    return send_error(conn, MHD_HTTP_NOT_FOUND, "未知接口");
}

static void completed(void *cls, struct MHD_Connection *conn, void **con_cls, enum MHD_RequestTerminationCode toe) {
    (void)cls; (void)conn; (void)toe;
    free_conn_context(*con_cls);
    *con_cls = NULL;
}

/* ==================== 定时清理线程 ==================== */
static void* cleanup_thread(void *arg) {
    (void)arg;
    printf("[AUTH] Cleanup thread started\n");
    while (g_running) {
        for (int i = 0; i < CLEANUP_INTERVAL && g_running; i++) sleep(1);
        if (!g_running) break;

        pthread_mutex_lock(&g_mutex);
        time_t now = time(NULL);
        int cleaned = 0;

        /* 清理过期验证码 */
        CodeNode *prev = NULL, *n = g_code_table;
        while (n) {
            if (n->expire_time < now) {
                CodeNode *del = n;
                if (prev) prev->next = n->next;
                else g_code_table = n->next;
                n = n->next; free(del); cleaned++; continue;
            }
            prev = n; n = n->next;
        }

        /* 清理过期/已完成的QR会话 */
        for (int i = 0; i < g_qr_session_count; i++) {
            if (g_qr_sessions[i].expires_at < now || g_qr_sessions[i].status == -1 || g_qr_sessions[i].status == 2) {
                g_qr_sessions[i] = g_qr_sessions[g_qr_session_count - 1];
                g_qr_session_count--;
                i--;
            }
        }

        /* 清理旧的失败锁定记录 */
        {
            FailLimitNode *fp = NULL, *fn = g_fail_limits;
            while (fn) {
                if (fn->lock_until > 0 && fn->lock_until + 3600 < now) {
                    FailLimitNode *del = fn;
                    if (fp) fp->next = fn->next;
                    else g_fail_limits = fn->next;
                    fn = fn->next; free(del); continue;
                }
                fp = fn; fn = fn->next;
            }
        }

        if (cleaned > 0) printf("[AUTH] Cleanup: removed %d expired codes\n", cleaned);
        pthread_mutex_unlock(&g_mutex);
    }
    printf("[AUTH] Cleanup thread stopped\n");
    return NULL;
}

/* ==================== 操作审计日志 ==================== */
#define AUDIT_LOG_FILE "/var/log/work_log/auth_audit.log"
static pthread_mutex_t g_audit_mutex = PTHREAD_MUTEX_INITIALIZER;

static void write_audit_log(const char *user, const char *action,
                            const char *ip, int success) {
    pthread_mutex_lock(&g_audit_mutex);
    FILE *fp = fopen(AUDIT_LOG_FILE, "a");
    if (fp) {
        time_t now = time(NULL);
        struct tm *lt = localtime(&now);
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", lt);
        /* 每行一条 JSON，方便 log_query 解析 */
        fprintf(fp, "{\"time\":\"%s\",\"user\":\"%s\",\"action\":\"%s\",\"ip\":\"%s\",\"success\":%s}\n",
                ts, user ? user : "-", action, ip ? ip : "-",
                success ? "true" : "false");
        fflush(fp);
        fclose(fp);
    }
    pthread_mutex_unlock(&g_audit_mutex);
}

/* ==================== 信号处理 ==================== */
static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) g_running = 0;
}

/* ==================== 主函数 ==================== */
int main(int argc, char *argv[]) {
    mkdir("/var/log/work_log", 0755);
    mkdir("/data", 0755);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* 加载统一配置 */
    load_config();

    /* 初始化认证通道 */
    printf("[AUTH] Initializing channels...\n");
    init_channel_sms();
    init_channel_email();
    init_channel_totp();
    init_channel_cert();

    /* 启动清理线程 */
    if (pthread_create(&g_cleanup_thread, NULL, cleanup_thread, NULL) == 0) {
        g_cleanup_started = 1;
    }

    /* 启动 MHD */
    int use_https = 1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--http") == 0) { use_https = 0; break; }
    }

    const char *cert_file = "/home/workspace/admin_auth/cert/server.crt";
    const char *key_file  = "/home/workspace/admin_auth/cert/server.key";
    char *cert_mem = NULL, *key_mem = NULL;

    if (use_https) {
        cert_mem = read_file_content(cert_file, NULL);
        key_mem  = read_file_content(key_file, NULL);
        if (!cert_mem || !key_mem) {
            fprintf(stderr, "错误: 无法读取证书文件\n");
            free(cert_mem); free(key_mem);
            return 1;
        }
    }

    struct MHD_Daemon *daemon = NULL;
    if (use_https) {
        daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_TLS,
            PORT, NULL, NULL, ahc, NULL,
            MHD_OPTION_HTTPS_MEM_CERT, cert_mem,
            MHD_OPTION_HTTPS_MEM_KEY, key_mem,
            MHD_OPTION_NOTIFY_COMPLETED, completed, NULL,
            MHD_OPTION_LISTENING_ADDRESS_REUSE, 1, MHD_OPTION_END);
    } else {
        daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
            PORT, NULL, NULL, ahc, NULL,
            MHD_OPTION_NOTIFY_COMPLETED, completed, NULL,
            MHD_OPTION_LISTENING_ADDRESS_REUSE, 1, MHD_OPTION_END);
    }

    if (!daemon) {
        fprintf(stderr, "服务启动失败\n");
        if (use_https) { free(cert_mem); free(key_mem); }
        return 1;
    }

    printf("==========================================\n");
    printf("  Auth 多通道认证服务已启动\n");
    printf("  端口: %d  协议: %s\n", PORT, use_https ? "HTTPS" : "HTTP");
    printf("  登录策略: %s (%s)\n", g_policy.login_policy,
           is_dual_factor_policy() ? "双因子" : "单因子");
    printf("  可用通道: password");
    if (g_sms_loaded) printf(", sms");
    if (g_email_loaded) printf(", email");
    if (g_totp_loaded) printf(", totp");
    if (g_cert_loaded) printf(", cert");
    if (is_channel_in_policy(g_policy.login_policy, "qrcode")) printf(", qrcode");
    printf("\n==========================================\n\n");
    printf("按 Ctrl+C 停止服务\n");

    while (g_running) sleep(1);

    /* 清理 */
    g_running = 0;
    if (g_cleanup_started) pthread_join(g_cleanup_thread, NULL);
    MHD_stop_daemon(daemon);

    if (g_sms_loaded)   sms_cleanup();
    if (g_email_loaded) email_cleanup();
    if (g_totp_loaded)  totp_cleanup();
    if (g_cert_loaded)  cert_cleanup();

    /* 释放内存 */
    { CodeNode *n = g_code_table; while (n) { CodeNode *t = n; n = n->next; free(t); } }
    { SendLimitNode *sn = g_send_limits; while (sn) { SendLimitNode *t = sn; sn = sn->next; free(t); } }
    { FailLimitNode *fn = g_fail_limits; while (fn) { FailLimitNode *t = fn; fn = fn->next; free(t); } }
    free(g_qr_sessions);
    free(g_rate_limits);
    if (g_module_menu) cJSON_Delete(g_module_menu);
    if (use_https) { free(cert_mem); free(key_mem); }

    return 0;
}
