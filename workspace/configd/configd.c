/*
 * configd - API 网关中间件 (HTTP 模式，配合 Nginx HTTPS 卸载)
 *
 * 部署架构:
 *   浏览器 → Nginx :443 (HTTPS卸载)
 *                ├── /api/*     → auth:8080   (认证服务)
 *                ├── /config/   → configd:8081 (API网关)
 *                ├── /health    → configd:8081 (健康检查)
 *                └── /          → 静态文件 + auth:8080
 *
 * Nginx 配置示例:
 *
 *   upstream auth_backend {
 *       server 127.0.0.1:8080;
 *       keepalive 64;
 *   }
 *   upstream configd_backend {
 *       server 127.0.0.1:8081;
 *       keepalive 64;
 *   }
 *
 *   server {
 *       listen 443 ssl;
 *       server_name your_domain.com;
 *
 *       ssl_certificate     /path/to/cert.pem;
 *       ssl_certificate_key /path/to/key.pem;
 *
 *       # SSL 安全响应头
 *       proxy_set_header Host              $host;
 *       proxy_set_header X-Real-IP         $remote_addr;
 *       proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
 *       proxy_set_header X-Forwarded-Proto $scheme;
 *       proxy_set_header X-Forwarded-Port  $server_port;
 *
 *       # 认证 API → auth 服务 (端口 8080)
 *       location /api/ {
 *           proxy_pass http://auth_backend;
 *       }
 *
 *       # configd API 网关 → configd (端口 8081)
 *       location /config/ {
 *           proxy_pass http://configd_backend;
 *       }
 *
 *       # 健康检查
 *       location /health {
 *           proxy_pass http://configd_backend/health;
 *       }
 *
 *       # 静态文件 + 前端
 *       location / {
 *           root /www/wwwroot/waywardkoi.cn;
 *           index index.html;
 *           try_files $uri $uri/ /index.html;
 *       }
 *   }
 *
 * 编译: make
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <signal.h>
#include <microhttpd.h>
#include <pthread.h>
#include <cjson/cJSON.h>

/* ========== 配置 ========== */
#define PORT 8081                // HTTP 监听端口，Nginx 将反向代理到此
#define JSON_DIR "/var/json"
#define LOG_FILE "/var/log/work_log/configd.log"
#define LOG_DIR "/var/log/work_log"
#define MAX_BODY_SIZE (1024 * 1024)
#define MAX_HEADER_SIZE 256

static FILE *g_log_fp = NULL;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* 路由条目 */
typedef struct {
    char action[128];
    char library[256];
    char function[128];
} RouteEntry;

static RouteEntry *g_routes = NULL;
static int g_route_count = 0;

/* ---------- Nginx 反向代理头解析 ---------- */
static void get_real_client_ip(struct MHD_Connection *conn, char *buf, size_t bufsize) {
    /* 优先级：X-Real-IP > X-Forwarded-For > 直接连接 IP */
    const union MHD_ConnectionInfo *info = MHD_get_connection_info(conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    const char *ip = NULL;

    /* 尝试从 Nginx 头获取 */
    ip = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-Real-IP");
    if (ip && strlen(ip) > 0) {
        snprintf(buf, bufsize, "%s", ip);
        return;
    }

    ip = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-Forwarded-For");
    if (ip && strlen(ip) > 0) {
        /* X-Forwarded-For 可能包含多个 IP，取第一个（最原始的客户端） */
        size_t len = strlen(ip);
        for (size_t i = 0; i < len; i++) {
            if (ip[i] == ',' || ip[i] == ' ') {
                size_t copy_len = i < bufsize - 1 ? i : bufsize - 1;
                memcpy(buf, ip, copy_len);
                buf[copy_len] = '\0';
                return;
            }
        }
        /* 没有分隔符：复制整个值（可能截断） */
        snprintf(buf, bufsize, "%s", ip);
        return;
    }

    /* 回退到直接连接的客户端地址 */
    if (info && info->client_addr) {
        if (info->client_addr->sa_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)info->client_addr;
            inet_ntop(AF_INET, &s->sin_addr, buf, bufsize);
            return;
        } else if (info->client_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)info->client_addr;
            inet_ntop(AF_INET6, &s6->sin6_addr, buf, bufsize);
            return;
        }
    }

    snprintf(buf, bufsize, "unknown");
}

static int is_https_from_nginx(struct MHD_Connection *conn) {
    const char *proto = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-Forwarded-Proto");
    if (proto && strcasecmp(proto, "https") == 0) {
        return 1;
    }
    /* X-Forwarded-Proto 明确为 http 时，不信任端口号 */
    if (proto && strcasecmp(proto, "http") == 0) {
        return 0;
    }
    /* 无 X-Forwarded-Proto 时，回退到端口判断 */
    const char *port = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-Forwarded-Port");
    if (port && atoi(port) == 443) {
        return 1;
    }
    return 0;
}

/* ---------- 动态库缓存 ---------- */
typedef struct LibCache {
    char *path;
    void *handle;
    int refcnt;
    struct LibCache *next;
} LibCache;

static LibCache *g_libcache = NULL;
static pthread_rwlock_t g_cache_lock = PTHREAD_RWLOCK_INITIALIZER;

static void *libcache_get(const char *path) {
    /* 先用读锁查找缓存 */
    pthread_rwlock_rdlock(&g_cache_lock);
    LibCache *cur = g_libcache;
    while (cur) {
        if (strcmp(cur->path, path) == 0) {
            cur->refcnt++;
            void *h = cur->handle;
            pthread_rwlock_unlock(&g_cache_lock);
            return h;
        }
        cur = cur->next;
    }
    pthread_rwlock_unlock(&g_cache_lock);

    /* 缓存未命中：在锁外 dlopen（避免长时间持锁阻塞其他请求） */
    void *h = dlopen(path, RTLD_LAZY | RTLD_NODELETE);
    if (!h) return NULL;

    /* 写锁插入缓存 */
    pthread_rwlock_wrlock(&g_cache_lock);
    /* 双重检查：可能有其他线程已加载 */
    cur = g_libcache;
    while (cur) {
        if (strcmp(cur->path, path) == 0) {
            cur->refcnt++;
            pthread_rwlock_unlock(&g_cache_lock);
            dlclose(h);  /* 重复加载，释放我们的 */
            return cur->handle;
        }
        cur = cur->next;
    }
    LibCache *node = calloc(1, sizeof(LibCache));
    if (!node) {
        pthread_rwlock_unlock(&g_cache_lock);
        dlclose(h);
        return NULL;
    }
    node->path = strdup(path);
    if (!node->path) {
        pthread_rwlock_unlock(&g_cache_lock);
        free(node);
        dlclose(h);
        return NULL;
    }
    node->handle = h;
    node->refcnt = 1;
    node->next = g_libcache;
    g_libcache = node;
    pthread_rwlock_unlock(&g_cache_lock);
    return h;
}

static void libcache_release(const char *path) {
    pthread_rwlock_wrlock(&g_cache_lock);
    LibCache **prev = &g_libcache;
    while (*prev) {
        if (strcmp((*prev)->path, path) == 0) {
            (*prev)->refcnt--;
            if ((*prev)->refcnt <= 0) {
                LibCache *victim = *prev;
                *prev = victim->next;
                dlclose(victim->handle);
                free(victim->path);
                free(victim);
            }
            pthread_rwlock_unlock(&g_cache_lock);
            return;
        }
        prev = &(*prev)->next;
    }
    pthread_rwlock_unlock(&g_cache_lock);
}

static void libcache_clear(void) {
    pthread_rwlock_wrlock(&g_cache_lock);
    LibCache *cur = g_libcache;
    while (cur) {
        LibCache *next = cur->next;
        dlclose(cur->handle);
        free(cur->path);
        free(cur);
        cur = next;
    }
    g_libcache = NULL;
    pthread_rwlock_unlock(&g_cache_lock);
}

/* ---------- 日志 ---------- */
static void log_write(const char *level, const char *fmt, ...) {
    pthread_mutex_lock(&g_log_mutex);
    if (!g_log_fp) {
        pthread_mutex_unlock(&g_log_mutex);
        fprintf(stderr, "[%s] ", level);
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
        fprintf(stderr, "\n");
        return;
    }
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    va_list args;
    va_start(args, fmt);
    fprintf(g_log_fp, "[%s] [%s] ", timestamp, level);
    vfprintf(g_log_fp, fmt, args);
    fprintf(g_log_fp, "\n");
    fflush(g_log_fp);
    pthread_mutex_unlock(&g_log_mutex);
    va_end(args);
}

#define LOG_INFO(fmt, ...)  log_write("INFO", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_write("ERROR", fmt, ##__VA_ARGS__)

static int safe_mkdir(const char *path) {
    if (mkdir(path, 0755) == -1 && errno != EEXIST) return -1;
    errno = 0;
    return 0;
}

static int init_log(void) {
    if (safe_mkdir(LOG_DIR) != 0) return -1;
    g_log_fp = fopen(LOG_FILE, "a");
    if (!g_log_fp) return -1;
    return 0;
}

static void close_log(void) {
    pthread_mutex_lock(&g_log_mutex);
    if (g_log_fp) { fclose(g_log_fp); g_log_fp = NULL; }
    pthread_mutex_unlock(&g_log_mutex);
}

/* ---------- 路由加载 ---------- */
static int load_routes_from_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        LOG_ERROR("无法打开 %s", path);
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size <= 0 || size > 1024*1024) { fclose(fp); return -1; }
    char *content = malloc(size + 1);
    if (!content) { fclose(fp); return -1; }
    if (fread(content, 1, size, fp) != (size_t)size) {
        free(content);
        fclose(fp);
        return -1;
    }
    content[size] = '\0';
    fclose(fp);

    /* 使用系统默认 cJSON 解析，已经验证过没有问题 */
    cJSON *root = cJSON_Parse(content);
    free(content);
    if (!root) {
        LOG_ERROR("JSON 解析失败: %s", path);
        return -1;
    }

    cJSON *routes = cJSON_GetObjectItem(root, "routes");
    if (!routes || !cJSON_IsArray(routes)) {
        LOG_ERROR("无效的 routes 数组: %s", path);
        cJSON_Delete(root);
        return -1;
    }

    int cnt = cJSON_GetArraySize(routes);
    for (int i = 0; i < cnt; i++) {
        cJSON *item = cJSON_GetArrayItem(routes, i);
        cJSON *action = cJSON_GetObjectItem(item, "action");
        cJSON *library = cJSON_GetObjectItem(item, "library");
        cJSON *function = cJSON_GetObjectItem(item, "function");
        if (!action || !cJSON_IsString(action) ||
            !library || !cJSON_IsString(library) ||
            !function || !cJSON_IsString(function)) {
            LOG_ERROR("路由项缺少必要字段: %s", path);
            continue;
        }

        RouteEntry *new_routes = realloc(g_routes, (g_route_count + 1) * sizeof(RouteEntry));
        if (!new_routes) {
            LOG_ERROR("内存分配失败");
            cJSON_Delete(root);
            return -1;
        }
        g_routes = new_routes;
        RouteEntry *e = &g_routes[g_route_count];
        snprintf(e->action, sizeof(e->action), "%s", action->valuestring);
        snprintf(e->library, sizeof(e->library), "%s", library->valuestring);
        snprintf(e->function, sizeof(e->function), "%s", function->valuestring);
        g_route_count++;
        LOG_INFO("加载路由: %s -> %s:%s", e->action, e->library, e->function);
    }
    cJSON_Delete(root);
    LOG_INFO("成功加载 %s", path);
    return 0;
}

static int load_all_routes(void) {
    DIR *dir = opendir(JSON_DIR);
    if (!dir) {
        LOG_ERROR("无法打开目录 %s，将以空路由表启动", JSON_DIR);
        return 0;  /* 不阻断启动，允许后续动态添加路由文件 */
    }
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        char *name = ent->d_name;
        int len = strlen(name);
        if (len < 5 || strcmp(name + len - 5, ".json") != 0) continue;
        char fullpath[512];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", JSON_DIR, name);
        /* 单个文件加载失败不中断，继续加载其他文件 */
        if (load_routes_from_file(fullpath) != 0) {
            LOG_ERROR("跳过无效路由文件: %s", fullpath);
        }
    }
    closedir(dir);

    /* 检查重复 action */
    for (int i = 0; i < g_route_count; i++) {
        for (int j = i + 1; j < g_route_count; j++) {
            if (strcmp(g_routes[i].action, g_routes[j].action) == 0) {
                LOG_ERROR("重复 action: %s (文件冲突，将使用最后注册的)", g_routes[i].action);
            }
        }
    }
    if (g_route_count == 0) {
        LOG_INFO("警告: 未加载到任何路由，请检查 %s 目录下的 .json 路由文件", JSON_DIR);
    } else {
        LOG_INFO("共加载 %d 条路由", g_route_count);
    }
    return 0;
}

static RouteEntry* find_route(const char *action) {
    for (int i = 0; i < g_route_count; i++)
        if (strcmp(g_routes[i].action, action) == 0) return &g_routes[i];
    return NULL;
}

static void free_routes(void) {
    if (g_routes) { free(g_routes); g_routes = NULL; }
    g_route_count = 0;
}

/* ---------- 库路径安全检查 ---------- */
#define TRUSTED_LIB_DIR "/lib/work_lib/"

static int is_path_safe(const char *libpath) {
    char resolved[PATH_MAX];
    if (!realpath(libpath, resolved)) {
        LOG_ERROR("is_path_safe: realpath 失败 path=%s (errno=%d: %s)",
                  libpath, errno, strerror(errno));
        return 0;
    }

    /* 同时解析受信目录，处理 /lib → /usr/lib 等符号链接 */
    char trusted_resolved[PATH_MAX];
    const char *trusted_prefix;
    if (realpath(TRUSTED_LIB_DIR, trusted_resolved)) {
        trusted_prefix = trusted_resolved;
    } else {
        trusted_prefix = TRUSTED_LIB_DIR;  /* 回退到字面值 */
    }

    size_t dir_len = strlen(trusted_prefix);
    if (strncmp(resolved, trusted_prefix, dir_len) != 0) {
        LOG_ERROR("is_path_safe: 路径不在受信目录 path=%s real=%s trusted=%s",
                  libpath, resolved, trusted_prefix);
        return 0;
    }
    /* 防止目录穿越（虽然 realpath 已解析，此处作为纵深防御） */
    if (strstr(resolved + dir_len, "..") != NULL) {
        LOG_ERROR("is_path_safe: 路径包含 .. path=%s real=%s", libpath, resolved);
        return 0;
    }

    LOG_INFO("is_path_safe: 通过 path=%s real=%s", libpath, resolved);
    return 1;
}

/* ---------- HTTP 辅助 ---------- */
static enum MHD_Result send_json_response(struct MHD_Connection *conn,
                                          int status,
                                          const char *json,
                                          size_t len) {
    struct MHD_Response *resp = MHD_create_response_from_buffer(len, (void *)json, MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        /* MHD 无法创建响应：释放调用方用 malloc 分配的 json 缓冲区 */
        free((void *)json);
        return MHD_NO;
    }
    MHD_add_response_header(resp, "Content-Type", "application/json");
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(resp, "Access-Control-Allow-Methods", "POST, OPTIONS");
    MHD_add_response_header(resp, "Access-Control-Allow-Headers", "Content-Type, Authorization");
    enum MHD_Result ret = MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp);
    return ret;
}

static char* create_error_json(int code, const char *msg) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "code", code);
    cJSON_AddStringToObject(obj, "message", msg);
    char *str = cJSON_Print(obj);
    cJSON_Delete(obj);
    return str;
}

/* ---------- 业务处理 ---------- */
static void process_request(struct MHD_Connection *conn, const char *post_data, const char *client_ip) {
    LOG_INFO("[%s] 收到请求", client_ip);

    cJSON *root = cJSON_Parse(post_data);
    if (!root) {
        char *resp = create_error_json(-3, "Invalid JSON");
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, resp, strlen(resp));
        return;
    }

    cJSON *action_obj = cJSON_GetObjectItem(root, "action");
    if (!action_obj || !cJSON_IsString(action_obj) || strlen(action_obj->valuestring) == 0) {
        LOG_ERROR("缺少 action");
        char *resp = create_error_json(-1, "Missing action");
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, resp, strlen(resp));
        cJSON_Delete(root);
        return;
    }

    const char *action = action_obj->valuestring;
    RouteEntry *route = find_route(action);
    if (!route) {
        LOG_ERROR("未知 action: %s", action);
        char *resp = create_error_json(-2, "Unknown action");
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, resp, strlen(resp));
        cJSON_Delete(root);
        return;
    }

    cJSON *data_obj = cJSON_GetObjectItem(root, "data");
    char *data_str = NULL;
    if (data_obj && cJSON_IsObject(data_obj))
        data_str = cJSON_PrintUnformatted(data_obj);
    else
        data_str = strdup("{}");
    cJSON_Delete(root);

    if (!is_path_safe(route->library)) {
        LOG_ERROR("插件路径不安全: %s", route->library);
        char *resp = create_error_json(-4, "Plugin path not allowed");
        send_json_response(conn, MHD_HTTP_FORBIDDEN, resp, strlen(resp));
        free(data_str);
        return;
    }

    void *handle = libcache_get(route->library);
    if (!handle) {
        LOG_ERROR("dlopen 失败: %s (错误: %s)", route->library, dlerror());
        char *resp = create_error_json(-4, "Plugin load failed");
        send_json_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, resp, strlen(resp));
        free(data_str);
        return;
    }

    typedef char* (*plugin_func)(const char*, int*);
    plugin_func func = (plugin_func)dlsym(handle, route->function);
    if (!func) {
        LOG_ERROR("dlsym 失败: %s (错误: %s)", route->function, dlerror());
        libcache_release(route->library);
        char *resp = create_error_json(-4, "Plugin function not found");
        send_json_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, resp, strlen(resp));
        free(data_str);
        return;
    }

    int http_status = 200;
    char *resp_body = func(data_str, &http_status);
    free(data_str);
    libcache_release(route->library);

    if (!resp_body) {
        resp_body = create_error_json(-99, "Plugin returned NULL");
        http_status = 500;
    }

    send_json_response(conn, http_status, resp_body, strlen(resp_body));
}

/* ---------- MHD 请求处理 ---------- */
struct ConnectionContext {
    char *post_data;
    size_t size;
    size_t cap;
    int body_received;  /* 1=body数据已全部到达（含空body） */
};

static enum MHD_Result ahc(void *cls, struct MHD_Connection *conn,
                          const char *url, const char *method,
                          const char *version, const char *upload_data,
                          size_t *upload_data_size, void **con_cls) {
    (void)cls; (void)version;

    /* 获取真实客户端 IP（Nginx 转发的） */
    char client_ip[64] = {0};
    get_real_client_ip(conn, client_ip, sizeof(client_ip));
    int is_https = is_https_from_nginx(conn);

    /* 健康检查端点 - Nginx 主动探测 /health 时返回 200 */
    if (strcmp(url, "/health") == 0 && strcmp(method, "GET") == 0) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "text/plain");
        MHD_add_response_header(resp, "X-Real-IP", client_ip);
        MHD_add_response_header(resp, "X-Forwarded-Proto", is_https ? "https" : "http");
        MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    /* 简单的状态页 - 显示服务基本信息和路由数量 */
    if (strcmp(url, "/status") == 0 && strcmp(method, "GET") == 0) {
        char status_json[256];
        snprintf(status_json, sizeof(status_json),
                 "{\"service\":\"configd\",\"status\":\"running\",\"routes\":%d}", g_route_count);
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(status_json), (void *)status_json, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        MHD_add_response_header(resp, "X-Real-IP", client_ip);
        MHD_add_response_header(resp, "X-Forwarded-Proto", is_https ? "https" : "http");
        MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(resp, "Access-Control-Allow-Credentials", "true");
        MHD_add_response_header(resp, "Access-Control-Allow-Methods", "POST, OPTIONS");
        MHD_add_response_header(resp, "Access-Control-Allow-Headers", "Content-Type, Authorization");
        MHD_add_response_header(resp, "Access-Control-Max-Age", "86400");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    if (strcmp(method, "POST") != 0) {
        char *resp = create_error_json(-1, "Only POST allowed");
        return send_json_response(conn, MHD_HTTP_BAD_REQUEST, resp, strlen(resp));
    }

    struct ConnectionContext *ctx = (struct ConnectionContext *)*con_cls;
    if (!ctx) {
        ctx = calloc(1, sizeof(struct ConnectionContext));
        if (!ctx) return MHD_NO;
        *con_cls = ctx;
    }

    if (*upload_data_size != 0) {
        if (ctx->size + *upload_data_size > MAX_BODY_SIZE) {
            free(ctx->post_data);
            free(ctx);
            *con_cls = NULL;
            char *resp = create_error_json(-5, "Request too large");
            return send_json_response(conn, MHD_HTTP_CONTENT_TOO_LARGE, resp, strlen(resp));
        }
        size_t new_size = ctx->size + *upload_data_size;
        if (new_size + 1 > ctx->cap) {
            ctx->cap = new_size + 1024;
            char *tmp = realloc(ctx->post_data, ctx->cap);
            if (!tmp) {
                /* realloc 失败：发送错误响应，而非静默关闭连接 */
                free(ctx->post_data);
                free(ctx);
                *con_cls = NULL;
                char *resp = create_error_json(-5, "Internal error: out of memory");
                return send_json_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, resp, strlen(resp));
            }
            ctx->post_data = tmp;
        }
        memcpy(ctx->post_data + ctx->size, upload_data, *upload_data_size);
        ctx->size += *upload_data_size;
        ctx->post_data[ctx->size] = '\0';
        *upload_data_size = 0;
        ctx->body_received = 1;  /* body 数据已全部到达 */
        return MHD_YES;
    }

    /*
     * upload_data_size == 0:
     * 可能是 MHD 第一次回调（body 还没到），也可能是 body 已全部接收完毕。
     * 通过 body_received 标志区分：
     *   - body_received == 0 → 等待 MHD 下一次带上 body 数据的回调
     *   - body_received == 1 → body 完整（或 Content-Length:0 的空 body）
     */
    if (!ctx->body_received) {
        /* 检查是否是真正的空 body（Content-Length: 0） */
        const char *cl = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Content-Length");
        if (cl && atoi(cl) == 0) {
            ctx->body_received = 1;
        } else {
            return MHD_YES;  /* 等待 body 数据到达 */
        }
    }

    /* body 已完整就绪，开始处理 */
    process_request(conn, ctx->post_data ? ctx->post_data : "{}", client_ip);
    free(ctx->post_data);
    free(ctx);
    *con_cls = NULL;
    return MHD_YES;
}

static void request_completed(void *cls, struct MHD_Connection *conn,
                             void **con_cls, enum MHD_RequestTerminationCode toe) {
    (void)cls; (void)conn; (void)toe;
    struct ConnectionContext *ctx = (struct ConnectionContext *)*con_cls;
    if (ctx) {
        if (ctx->post_data) free(ctx->post_data);
        free(ctx);
        *con_cls = NULL;
    }
}

/* ---------- 守护进程 ---------- */
static void daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    setsid();
    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    chdir("/");
    close(0);
    int fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        dup2(fd, 1);
        dup2(fd, 2);
        close(fd);
    } else {
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, 0);
            dup2(devnull, 1);
            dup2(devnull, 2);
            close(devnull);
        }
    }
}

/* ---------- 主程序 ---------- */
static volatile int g_running = 1;
static struct MHD_Daemon *g_daemon = NULL;

static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        g_running = 0;
        /* 不在信号处理器中调用 MHD_stop_daemon（非异步信号安全）；
         * 主循环在 sleep(1) 后会检查 g_running 并正常关闭。 */
    }
}

int main(int argc, char *argv[]) {
    int daemon_mode = 0;
    if (argc > 1 && strcmp(argv[1], "-d") == 0) daemon_mode = 1;

    if (init_log() != 0) {
        fprintf(stderr, "日志初始化失败\n");
        return 1;
    }
    if (safe_mkdir(JSON_DIR) != 0) {
        fprintf(stderr, "无法创建配置目录 %s\n", JSON_DIR);
        close_log();
        return 1;
    }
    if (load_all_routes() != 0) {
        LOG_ERROR("路由加载失败");
        free_routes();
        close_log();
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (daemon_mode) daemonize();

    /* 纯 HTTP 模式，无 TLS，使用最稳定的单线程 select 模型 */
    g_daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY,
        PORT,
        NULL, NULL,
        ahc, NULL,
        MHD_OPTION_NOTIFY_COMPLETED, request_completed,
        MHD_OPTION_LISTENING_ADDRESS_REUSE, 1,
        MHD_OPTION_END);

    if (!g_daemon) {
        LOG_ERROR("服务启动失败，端口 %d", PORT);
        fprintf(stderr, "服务启动失败，端口 %d\n", PORT);
        free_routes();
        close_log();
        return 1;
    }

    LOG_INFO("configd 已启动，端口 %d (HTTP)", PORT);
    printf("configd 已启动，端口 %d (HTTP)\n", PORT);
    if (!daemon_mode) printf("按 Ctrl+C 停止\n");

    while (g_running) sleep(1);

    MHD_stop_daemon(g_daemon);
    libcache_clear();
    free_routes();
    close_log();
    printf("configd 已退出\n");
    return 0;
}