/*
 * Email 验证码发送模块 - 腾讯云 SES API v3
 * 编译: gcc -shared -fPIC -o libemail.so email.c -lcurl -lssl -lcrypto -lcjson -Wall -O2
 * 配置文件: /etc/email.conf (JSON)
 * {
 *   "secret_id":"AKIDxxxx", "secret_key":"xxxx",
 *   "from_address":"noreply@yourdomain.com",
 *   "from_alias":"IoT Platform",
 *   "subject":"IoT Platform 登录验证码",
 *   "template_id":186757,
 *   "region":"ap-hongkong"
 * }
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <cjson/cJSON.h>

#define EMAIL_CONF   "/etc/email.conf"
#define ENDPOINT     "ses.tencentcloudapi.com"
#define API_VERSION  "2020-10-02"

static int  g_init = 0;
static char g_sid[128]   = {0};
static char g_skey[128]  = {0};
static char g_from[128]  = {0};
static char g_alias[64]  = {0};
static char g_subj[128]  = {0};
static int  g_tpl_id     = 0;
static char g_region[32] = {0};

/* ---- log ---- */
static void elog(const char *fmt, ...) {
    char m[1024]; va_list a; va_start(a,fmt); vsnprintf(m,sizeof(m),fmt,a); va_end(a);
    fprintf(stderr,"[EMAIL] %s\n",m);
    mkdir("/var/log/work_log",0755);
    FILE *f=fopen("/var/log/work_log/auth.log","a");
    if(f){ time_t n=time(NULL); struct tm *t=localtime(&n);
        fprintf(f,"[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                t->tm_year+1900,t->tm_mon+1,t->tm_mday,t->tm_hour,t->tm_min,t->tm_sec,m); fclose(f); }
}

/* ---- 官方示例的辅助函数（完全拷贝） ---- */
static void get_utc_date(time_t timestamp, char* utc, int len) {
    struct tm sttime;
    sttime = *gmtime(&timestamp);
    strftime(utc, len, "%Y-%m-%d", &sttime);
}

static void sha256_hex(const char* str, char* result) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, strlen(str));
    SHA256_Final(hash, &sha256);
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(result + i*2, "%02x", hash[i]);
    }
}

static void hmac_sha256(const char* key, int key_len,
                        const char* input, int input_len,
                        unsigned char* output, unsigned int* output_len) {
    HMAC_CTX *h;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);
    h = &hmac;
#else
    h = HMAC_CTX_new();
#endif
    HMAC_Init_ex(h, key, key_len, EVP_sha256(), NULL);
    HMAC_Update(h, (const unsigned char*)input, input_len);
    HMAC_Final(h, output, output_len);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_cleanup(h);
#else
    HMAC_CTX_free(h);
#endif
}

static void hex_encode(const unsigned char* input, int input_len, char* output) {
    static const char* const lut = "0123456789abcdef";
    for (int i = 0; i < input_len; ++i) {
        output[i*2] = lut[input[i] >> 4];
        output[i*2+1] = lut[input[i] & 15];
    }
    output[input_len*2] = '\0';
}

static void lowercase(const char * src, char * dst) {
    for (int i = 0; src[i]; i++) {
        dst[i] = tolower(src[i]);
    }
}

/* ---- 基于官方示例的 TC3 签名生成（替换原 tc3_sign） ---- */
static char* tc3_sign(const char *secret_id, const char *secret_key,
                      const char *service, const char *action,
                      const char *host, const char *region,
                      const char *payload) {
    (void)region; // 在本签名中未直接使用，但保留参数一致性

    time_t now = time(NULL);
    char date[20] = {0}, timestamp_str[16] = {0};
    get_utc_date(now, date, sizeof(date));
    snprintf(timestamp_str, sizeof(timestamp_str), "%ld", (long)now);

    // 步骤1：拼接规范请求串
    char canonical_headers[512] = {0};
    char action_lower[64] = {0};
    lowercase(action, action_lower);
    snprintf(canonical_headers, sizeof(canonical_headers),
             "content-type:application/json\nhost:%s\nx-tc-action:%s\n",
             host, action_lower);

    char hashed_payload[65] = {0};
    sha256_hex(payload, hashed_payload);

    const char* signed_headers = "content-type;host;x-tc-action";
    char canonical_request[2048] = {0};
    snprintf(canonical_request, sizeof(canonical_request),
             "POST\n/\n\n%s\n%s\n%s",
             canonical_headers, signed_headers, hashed_payload);

    // 步骤2：拼接待签名字符串
    char hashed_canonical[65] = {0};
    sha256_hex(canonical_request, hashed_canonical);
    char credential_scope[128] = {0};
    snprintf(credential_scope, sizeof(credential_scope), "%s/%s/tc3_request", date, service);
    char string_to_sign[512] = {0};
    snprintf(string_to_sign, sizeof(string_to_sign),
             "TC3-HMAC-SHA256\n%s\n%s\n%s",
             timestamp_str, credential_scope, hashed_canonical);

    // 步骤3：计算签名
    unsigned char k_date[32], k_service[32], k_signing[32], signature_raw[32];
    unsigned int len = 32;
    char k_key[128] = {0};
    snprintf(k_key, sizeof(k_key), "TC3%s", secret_key);
    hmac_sha256(k_key, strlen(k_key), date, strlen(date), k_date, &len);
    hmac_sha256((const char*)k_date, len, service, strlen(service), k_service, &len);
    hmac_sha256((const char*)k_service, len, "tc3_request", strlen("tc3_request"), k_signing, &len);
    hmac_sha256((const char*)k_signing, len, string_to_sign, strlen(string_to_sign), signature_raw, &len);
    char signature[65] = {0};
    hex_encode(signature_raw, len, signature);

    // 步骤4：拼接 Authorization
    char *auth = malloc(1024);
    if (!auth) return NULL;
    snprintf(auth, 1024,
             "TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
             secret_id, credential_scope, signed_headers, signature);
    return auth;
}

/* ---- 以下为 curl write 回调（未改动） ---- */
struct bc { char *d; size_t l,c; };
static size_t wcb(void *p, size_t s, size_t n, void *u) {
    struct bc *b=(struct bc*)u; size_t t=s*n;
    if(b->l+t+1>b->c){ size_t nc=b->c*2>b->l+t+1?b->c*2:b->l+t+1;
        char *tmp=realloc(b->d,nc); if(!tmp)return 0; b->d=tmp; b->c=nc; }
    memcpy(b->d+b->l,p,t); b->l+=t; b->d[b->l]='\0'; return t;
}

/* ---- load config (未改动) ---- */
static int load_cfg(void) {
    FILE *f=fopen(EMAIL_CONF,"r"); if(!f){elog("无法打开 %s",EMAIL_CONF);return -1;}
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    if(sz<=0){fclose(f);return -1;}
    char *b=malloc(sz+1); if(!b){fclose(f);return -1;}
    size_t n=fread(b,1,sz,f); b[n]='\0'; fclose(f);
    cJSON *r=cJSON_Parse(b); free(b); if(!r)return -1;
    cJSON *v;
    v=cJSON_GetObjectItem(r,"secret_id");       if(v&&cJSON_IsString(v)) strncpy(g_sid,v->valuestring,sizeof(g_sid)-1);
    v=cJSON_GetObjectItem(r,"secret_key");      if(v&&cJSON_IsString(v)) strncpy(g_skey,v->valuestring,sizeof(g_skey)-1);
    v=cJSON_GetObjectItem(r,"from_address");    if(v&&cJSON_IsString(v)) strncpy(g_from,v->valuestring,sizeof(g_from)-1);
    v=cJSON_GetObjectItem(r,"from_alias");      if(v&&cJSON_IsString(v)) strncpy(g_alias,v->valuestring,sizeof(g_alias)-1);
    v=cJSON_GetObjectItem(r,"subject");         if(v&&cJSON_IsString(v)) strncpy(g_subj,v->valuestring,sizeof(g_subj)-1);
    v=cJSON_GetObjectItem(r,"template_id");     if(v&&cJSON_IsNumber(v)) g_tpl_id=(int)v->valuedouble;
    v=cJSON_GetObjectItem(r,"region");          if(v&&cJSON_IsString(v)) strncpy(g_region,v->valuestring,sizeof(g_region)-1);
    cJSON_Delete(r);
    if(!g_sid[0]||!g_skey[0]||!g_from[0]){elog("配置不完整");return -1;}
    if(!g_region[0]) strncpy(g_region,"ap-hongkong",sizeof(g_region)-1);
    if(g_tpl_id<=0){elog("template_id 必须配置");return -1;}
    elog("配置OK from=%s tpl=%d region=%s",g_from,g_tpl_id,g_region);
    return 0;
}

/* ==================== Public API ==================== */

int email_init(const char *cfg) {
    (void)cfg; if(g_init)return 0;
    if(load_cfg()!=0)return -1;
    curl_global_init(CURL_GLOBAL_ALL);
    g_init=1; elog("腾讯云邮件模块就绪"); return 0;
}

int email_send_code(const char *to, const char *username, const char *code) {
    if(!g_init){elog("未初始化");return -1;}
    if(!to || !username || !code || !*to || !*username || !*code){elog("参数无效");return -1;}
    elog("发送: To=%s, Username=%s, Code=%s", to, username, code);

    char body[4096];
    snprintf(body, sizeof(body),
        "{\"FromEmailAddress\":\"%s\","
        "\"Destination\":[\"%s\"],"
        "\"Subject\":\"%s\","
        "\"Template\":{"
            "\"TemplateID\":%d,"
            "\"TemplateData\":\"{\\\"username\\\":\\\"%s\\\",\\\"code\\\":\\\"%s\\\"}\""
        "}}",
        g_from, to, g_subj, g_tpl_id, username, code);

    /* 调用新签名函数，传递 ENDPOINT 作为 host，g_region 保留但未在签名中使用 */
    char *auth = tc3_sign(g_sid, g_skey, "ses", "SendEmail", ENDPOINT, g_region, body);
    if(!auth){elog("签名失败"); return -1;}

    time_t now=time(NULL);

    CURL *c=curl_easy_init(); if(!c){free(auth);return -1;}
    struct curl_slist *h=NULL;
    char ha[2048]; snprintf(ha,sizeof(ha),"Authorization: %s",auth);
    h = curl_slist_append(h, "Host: ses.tencentcloudapi.com");
    h = curl_slist_append(h, "Content-Type: application/json");   // 不带 charset
    h = curl_slist_append(h, ha);
    char hx[256];
    snprintf(hx,sizeof(hx),"X-TC-Action: SendEmail"); h = curl_slist_append(h, hx);
    snprintf(hx,sizeof(hx),"X-TC-Version: %s",API_VERSION); h = curl_slist_append(h, hx);
    snprintf(hx,sizeof(hx),"X-TC-Timestamp: %ld",(long)now); h = curl_slist_append(h, hx);
    snprintf(hx,sizeof(hx),"X-TC-Region: %s",g_region); h = curl_slist_append(h, hx);

    struct bc resp; memset(&resp,0,sizeof(resp));
    resp.d=malloc(4096); resp.c=4096;

    curl_easy_setopt(c,CURLOPT_URL,"https://" ENDPOINT);
    curl_easy_setopt(c,CURLOPT_HTTPHEADER,h);
    curl_easy_setopt(c,CURLOPT_POSTFIELDS,body);
    curl_easy_setopt(c,CURLOPT_WRITEFUNCTION,wcb);
    curl_easy_setopt(c,CURLOPT_WRITEDATA,&resp);
    curl_easy_setopt(c,CURLOPT_TIMEOUT,8L);

    CURLcode cr=curl_easy_perform(c);
    int ret=-1;
    if(cr!=CURLE_OK){elog("curl error: %s",curl_easy_strerror(cr));ret=-2;}
    else{
        long st=0; curl_easy_getinfo(c,CURLINFO_RESPONSE_CODE,&st);
        elog("HTTP %ld: %s",st,resp.d?resp.d:"(empty)");
        if(st==200 && resp.d && strstr(resp.d,"\"MessageId\"")) {
            ret=0;
        } else {
            ret=-3;
        }
    }
    curl_slist_free_all(h); free(auth); free(resp.d); curl_easy_cleanup(c);
    return ret;
}

void email_cleanup(void) {
    if(g_init){curl_global_cleanup();g_init=0;}
    elog("模块已清理");
}