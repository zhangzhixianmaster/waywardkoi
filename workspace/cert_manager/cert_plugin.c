/*
 * cert_plugin.c - 证书管理插件 (configd 加载)
 * 编译: gcc -shared -fPIC -o libcert_manager.so cert_plugin.c -lcjson -lssl -lcrypto -Wall -O2
 *
 * 接口列表:
 *   list_certs         - 证书列表(分页+搜索)
 *   get_available_certs - 可绑定证书列表
 *   create_cert        - 申请证书
 *   get_cert_detail    - 证书详情
 *   download_cert      - 下载证书(PEM/P12)
 *   revoke_cert        - 吊销证书
 *   delete_cert        - 删除证书
 *   resend_cert_email  - 重发证书邮件
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cjson/cJSON.h>

/* ========== 常量 ========== */
#define CERTS_DIR      "/data/certs"
#define CERTS_JSON     "/data/certs/certs.json"
#define CA_CRT         "/data/certs/ca/ca.crt"
#define CA_KEY         "/data/certs/ca/ca.key"
#define ADMINS_JSON    "/data/admins.json"
#define LOG_FILE       "/var/log/work_log/auth.log"

/* ========== 日志 ========== */
static void plog(const char *fmt, ...) {
    char m[1024]; va_list a; va_start(a,fmt); vsnprintf(m,sizeof(m),fmt,a); va_end(a);
    fprintf(stderr,"[CERT] %s\n",m);
    FILE *f=fopen(LOG_FILE,"a");
    if(f){ time_t n=time(NULL); struct tm *t=localtime(&n);
        fprintf(f,"[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                t->tm_year+1900,t->tm_mon+1,t->tm_mday,t->tm_hour,t->tm_min,t->tm_sec,m); fclose(f); }
}

/* ========== 辅助函数 ========== */
static char* create_response(int code, const char *message, cJSON *data) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "code", code);
    cJSON_AddStringToObject(obj, "message", message);
    if (data) cJSON_AddItemToObject(obj, "data", data);
    else cJSON_AddNullToObject(obj, "data");
    char *s = cJSON_Print(obj); cJSON_Delete(obj); return s;
}

static char* read_file(const char *path, long *out_len) {
    FILE *f = fopen(path, "rb"); if (!f) return NULL;
    fseek(f,0,SEEK_END); long len=ftell(f); fseek(f,0,SEEK_SET);
    if (len<=0) { fclose(f); return NULL; }
    char *b=malloc(len+1); if(!b){fclose(f);return NULL;}
    fread(b,1,len,f); b[len]='\0'; fclose(f);
    if(out_len) *out_len=len; return b;
}

static int file_exists(const char *path) { return access(path, F_OK)==0; }

static void ensure_dir(const char *dir) { mkdir(dir, 0755); }

static cJSON* load_certs_json(void) {
    ensure_dir(CERTS_DIR); ensure_dir("/data/certs/ca"); ensure_dir("/data/certs/certs");
    cJSON *root = NULL;
    FILE *f = fopen(CERTS_JSON, "r");
    if (f) { fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
        if(sz>0){ char *b=malloc(sz+1); if(b){ fread(b,1,sz,f); b[sz]='\0'; root=cJSON_Parse(b); free(b); } }
        fclose(f); }
    if (!root) { root = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "certs", cJSON_CreateArray());
        cJSON_AddNumberToObject(root, "cert_sequence", 0); }
    return root;
}

static void save_certs_json(cJSON *root) {
    ensure_dir(CERTS_DIR);
    char *s = cJSON_Print(root);
    if (s) { FILE *f = fopen(CERTS_JSON, "w"); if(f){ fprintf(f,"%s",s); fclose(f); } free(s); }
}

static cJSON* find_cert(cJSON *root, const char *id) {
    cJSON *certs = cJSON_GetObjectItem(root, "certs");
    cJSON *item; cJSON_ArrayForEach(item, certs) {
        cJSON *cid = cJSON_GetObjectItem(item, "id");
        if (cid && cJSON_IsString(cid) && strcmp(cid->valuestring, id)==0) return item;
    }
    return NULL;
}

static void generate_uuid(char *out) {
    FILE *f = fopen("/proc/sys/kernel/random/uuid", "r");
    if (f) { fgets(out, 37, f); fclose(f); return; }
    /* fallback */
    sprintf(out, "%08x-%04x-%04x-%04x-%012lx",
            (unsigned)time(NULL), (unsigned)(time(NULL)>>16)&0xFFFF,
            (unsigned)(time(NULL)>>16)&0xFFFF, (unsigned)(time(NULL)>>16)&0xFFFF,
            (unsigned long)time(NULL));
}

static int is_cert_valid(cJSON *cert) {
    if (!cert) return 0;
    cJSON *status = cJSON_GetObjectItem(cert, "status");
    cJSON *valid_to = cJSON_GetObjectItem(cert, "valid_to");
    if (!status || strcmp(status->valuestring, "valid") != 0) return 0;
    if (valid_to) {
        struct tm tm = {0}; int y,m,d; sscanf(valid_to->valuestring, "%d-%d-%dT", &y,&m,&d);
        time_t vt = mktime(&(struct tm){.tm_year=y-1900,.tm_mon=m-1,.tm_mday=d,.tm_hour=23,.tm_min=59});
        if (time(NULL) > vt) return 0;
    }
    return 1;
}

static const char* cert_status_label(cJSON *cert) {
    cJSON *status = cJSON_GetObjectItem(cert, "status");
    if (status && strcmp(status->valuestring, "revoked")==0) return "已吊销";
    if (!is_cert_valid(cert)) return "已过期";
    cJSON *vt = cJSON_GetObjectItem(cert, "valid_to");
    if (vt) { struct tm tm={0}; int y,m,d; sscanf(vt->valuestring,"%d-%d-%dT",&y,&m,&d);
        time_t vt_t=mktime(&(struct tm){.tm_year=y-1900,.tm_mon=m-1,.tm_mday=d});
        if ((vt_t-time(NULL))/(86400) <= 30) return "即将过期"; }
    return "有效";
}

/* ========== 根证书初始化 ========== */
int cert_init_root(void) {
    ensure_dir("/data/certs/ca");
    if (file_exists(CA_CRT) && file_exists(CA_KEY)) return 0;
    plog("初始化根证书...");
    system("openssl genrsa -out " CA_KEY " 2048 2>/dev/null");
    system("openssl req -x509 -new -nodes -key " CA_KEY " -sha256 -days 3650 "
           "-subj \"/CN=IoT Platform Root CA/O=IoT Platform/C=CN\" "
           "-out " CA_CRT " 2>/dev/null");
    chmod(CA_KEY, 0600);
    if (file_exists(CA_CRT)) { plog("根证书已生成"); return 0; }
    plog("根证书生成失败"); return -1;
}

/* ========== 生成证书 ========== */
static int generate_cert(const char *cn, const char *o, const char *ou,
                          int valid_days, const char *algo, const char *cert_dir) {
    char cmd[2048];
    char key_path[512], crt_path[512], p12_path[512];
    snprintf(key_path, sizeof(key_path), "%s/cert.key", cert_dir);
    snprintf(crt_path, sizeof(crt_path), "%s/cert.crt", cert_dir);
    snprintf(p12_path, sizeof(p12_path), "%s/cert.p12", cert_dir);

    int key_bits = 2048;
    if (strstr(algo, "4096")) key_bits = 4096;

    snprintf(cmd, sizeof(cmd),
        "openssl req -newkey rsa:%d -nodes -keyout %s -out /tmp/cert_csr.pem "
        "-subj \"/CN=%s/O=%s/OU=%s\" 2>/dev/null && "
        "openssl x509 -req -in /tmp/cert_csr.pem -CA " CA_CRT " -CAkey " CA_KEY
        " -CAcreateserial -out %s -days %d -sha256 2>/dev/null && "
        "openssl pkcs12 -export -in %s -inkey %s -out %s -passout pass:changeme 2>/dev/null",
        key_bits, key_path, cn, o ? o : "IoT Platform", ou ? ou : "Security",
        crt_path, valid_days, crt_path, key_path, p12_path);

    int ret = system(cmd);
    chmod(key_path, 0600);
    unlink("/tmp/cert_csr.pem");
    return (ret == 0 && file_exists(crt_path)) ? 0 : -1;
}

static char* get_cert_fingerprint(const char *crt_path) {
    char cmd[512], buf[256]={0};
    snprintf(cmd,sizeof(cmd),"openssl x509 -in %s -noout -fingerprint -sha256 2>/dev/null",crt_path);
    FILE *f=popen(cmd,"r"); if(f){ fgets(buf,sizeof(buf),f); pclose(f); }
    char *fp = strstr(buf, "="); if (fp) fp++; else fp = buf;
    char *out=malloc(96); if(!out)return NULL;
    char *d=out; for(char *c=fp;*c;c++) if(*c!=':'&&*c!=' '&&*c!='\n') *d++=*c; *d='\0';
    return out;
}

static char* get_cert_serial(const char *crt_path) {
    char cmd[512], buf[256]={0};
    snprintf(cmd,sizeof(cmd),"openssl x509 -in %s -noout -serial 2>/dev/null",crt_path);
    FILE *f=popen(cmd,"r"); if(f){ fgets(buf,sizeof(buf),f); pclose(f); }
    char *p=strstr(buf,"="); if(p) return strdup(p+1);
    return strdup("unknown");
}

/* ========== API: list_certs ========== */
char* list_certs(const char *data_json, int *out_status) {
    int page=1, size=20;
    char keyword[128]={0};
    cJSON *req = cJSON_Parse(data_json);
    if (req) {
        cJSON *v = cJSON_GetObjectItem(req,"page"); if(v) page=(int)v->valuedouble;
        v = cJSON_GetObjectItem(req,"size"); if(v) size=(int)v->valuedouble;
        v = cJSON_GetObjectItem(req,"keyword"); if(v && cJSON_IsString(v))
            strncpy(keyword, v->valuestring, sizeof(keyword)-1);
        cJSON_Delete(req);
    }
    if (page<1) page=1; if (size<1||size>100) size=20;

    cJSON *root = load_certs_json();
    cJSON *certs = cJSON_GetObjectItem(root, "certs");
    cJSON *result_list = cJSON_CreateArray();
    int total=0, valid=0, expired=0, revoked=0;
    cJSON *item; cJSON_ArrayForEach(item, certs) {
        /* 状态统计 */
        cJSON *st = cJSON_GetObjectItem(item, "status");
        if (st && strcmp(st->valuestring,"revoked")==0) revoked++;
        else if (is_cert_valid(item)) valid++;
        else expired++;
        total++;
    }

    /* 过滤+分页 */
    int idx=0, shown=0;
    cJSON *item2; cJSON_ArrayForEach(item2, certs) {
        cJSON *name = cJSON_GetObjectItem(item2, "name");
        if (keyword[0] && name && !strstr(name->valuestring, keyword)) continue;
        idx++;
        if (idx <= (page-1)*size) continue;
        if (shown >= size) continue;

        cJSON *entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "id",    cJSON_GetObjectItem(item2,"id")->valuestring);
        cJSON_AddStringToObject(entry, "name",  name ? name->valuestring : "");
        cJSON_AddStringToObject(entry, "cn",    cJSON_GetObjectItem(item2,"cn") ? cJSON_GetObjectItem(item2,"cn")->valuestring : "");
        cJSON *iss = cJSON_GetObjectItem(item2, "issuer_cn");
        cJSON_AddStringToObject(entry, "issuer", iss ? iss->valuestring : "");
        cJSON *pur = cJSON_GetObjectItem(item2, "purpose");
        cJSON_AddStringToObject(entry, "purpose", pur ? pur->valuestring : "");
        cJSON_AddStringToObject(entry, "valid_to", cJSON_GetObjectItem(item2,"valid_to")->valuestring);
        cJSON_AddStringToObject(entry, "status", cJSON_GetObjectItem(item2,"status")->valuestring);
        cJSON_AddStringToObject(entry, "status_label", cert_status_label(item2));
        cJSON *bt = cJSON_GetObjectItem(item2, "bound_to");
        cJSON_AddStringToObject(entry, "bound_to", (bt&&cJSON_IsString(bt))?bt->valuestring:"");
        cJSON *ca = cJSON_GetObjectItem(item2, "created_at");
        cJSON_AddStringToObject(entry, "created_at", ca?ca->valuestring:"");
        cJSON_AddItemToArray(result_list, entry);
        shown++;
    }

    cJSON *data = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "certs", result_list);
    cJSON_AddNumberToObject(data, "total", total);
    cJSON_AddNumberToObject(data, "valid", valid);
    cJSON_AddNumberToObject(data, "expired", expired);
    cJSON_AddNumberToObject(data, "revoked", revoked);
    cJSON_AddNumberToObject(data, "page", page);
    cJSON_AddNumberToObject(data, "size", size);
    cJSON_Delete(root);
    *out_status = 200;
    return create_response(0, "success", data);
}

/* ========== API: get_available_certs (供管理员绑定) ========== */
char* get_available_certs(const char *data_json, int *out_status) {
    (void)data_json;
    cJSON *root = load_certs_json();
    cJSON *certs = cJSON_GetObjectItem(root, "certs");
    cJSON *result = cJSON_CreateArray();
    cJSON *item; cJSON_ArrayForEach(item, certs) {
        if (!is_cert_valid(item)) continue;
        cJSON *pur = cJSON_GetObjectItem(item, "purpose");
        if (!pur || strcmp(pur->valuestring, "admin_login")!=0) continue;
        cJSON *bound = cJSON_GetObjectItem(item, "bound_to");
        if (bound && cJSON_IsString(bound) && strlen(bound->valuestring)>0) continue;
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "id",   cJSON_GetObjectItem(item,"id")->valuestring);
        cJSON_AddStringToObject(entry, "name", cJSON_GetObjectItem(item,"name")->valuestring);
        cJSON_AddStringToObject(entry, "cn",   cJSON_GetObjectItem(item,"cn")->valuestring);
        cJSON_AddItemToArray(result, entry);
    }
    cJSON *data = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "certs", result);
    cJSON_Delete(root);
    *out_status = 200;
    return create_response(0, "success", data);
}

/* ========== API: create_cert ========== */
char* create_cert(const char *data_json, int *out_status) {
    cJSON *req = cJSON_Parse(data_json);
    if (!req) { *out_status=400; return create_response(-1,"Invalid JSON",NULL); }

    cJSON *name_o = cJSON_GetObjectItem(req,"name");
    cJSON *cn_o   = cJSON_GetObjectItem(req,"cn");
    if (!name_o || !cJSON_IsString(name_o) || strlen(name_o->valuestring)==0) {
        cJSON_Delete(req); *out_status=400; return create_response(1002,"CN/名称不能为空",NULL); }

    const char *name = name_o->valuestring;
    const char *cn   = (cn_o && cJSON_IsString(cn_o)) ? cn_o->valuestring : name;
    const char *o  = "IoT Platform"; const char *ou="Security"; const char *algo="RSA 2048";
    int years=1;
    cJSON *v; v=cJSON_GetObjectItem(req,"o"); if(v&&cJSON_IsString(v)) o=v->valuestring;
    v=cJSON_GetObjectItem(req,"ou"); if(v&&cJSON_IsString(v)) ou=v->valuestring;
    v=cJSON_GetObjectItem(req,"valid_years"); if(v) years=(int)v->valuedouble;
    if(years<1) years=1; if(years>10) years=10;
    v=cJSON_GetObjectItem(req,"algorithm"); if(v&&cJSON_IsString(v)) algo=v->valuestring;

    /* 检查名称唯一性 */
    cJSON *root = load_certs_json();
    cJSON *certs = cJSON_GetObjectItem(root, "certs");
    cJSON *item; cJSON_ArrayForEach(item, certs) {
        cJSON *n = cJSON_GetObjectItem(item, "name");
        if (n && strcmp(n->valuestring, name)==0) {
            cJSON_Delete(req); cJSON_Delete(root); *out_status=400;
            return create_response(1001,"证书名称已存在",NULL); }
    }

    /* 根证书检查 */
    if (!file_exists(CA_KEY) || !file_exists(CA_CRT)) cert_init_root();
    if (!file_exists(CA_KEY)) { cJSON_Delete(req); cJSON_Delete(root); *out_status=500;
        return create_response(1003,"根证书未初始化",NULL); }

    /* 生成 UUID */
    char uuid[40]; generate_uuid(uuid);
    char cert_dir[256]; snprintf(cert_dir,sizeof(cert_dir),"/data/certs/certs/%s",uuid);
    ensure_dir(cert_dir);

    /* 生成证书 */
    if (generate_cert(cn, o, ou, years*365, algo, cert_dir) != 0) {
        cJSON_Delete(req); cJSON_Delete(root); *out_status=500;
        return create_response(1004,"证书生成失败",NULL); }

    /* 读取指纹 */
    char crt_path[512]; snprintf(crt_path,sizeof(crt_path),"%s/cert.crt",cert_dir);
    char *fp = get_cert_fingerprint(crt_path);
    char *serial = get_cert_serial(crt_path);

    /* 构建元数据 */
    time_t now = time(NULL); char ts[64], vt_ts[64];
    strftime(ts,sizeof(ts),"%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    time_t vt = now + years*365*86400;
    strftime(vt_ts,sizeof(vt_ts),"%Y-%m-%dT%H:%M:%SZ", gmtime(&vt));

    cJSON *new_cert = cJSON_CreateObject();
    cJSON_AddStringToObject(new_cert, "id", uuid);
    cJSON_AddStringToObject(new_cert, "name", name);
    cJSON_AddStringToObject(new_cert, "purpose", "admin_login");
    cJSON_AddStringToObject(new_cert, "cn", cn);
    cJSON_AddStringToObject(new_cert, "o", o);
    cJSON_AddStringToObject(new_cert, "ou", ou);
    cJSON_AddStringToObject(new_cert, "issuer_cn", "IoT Platform Root CA");
    cJSON_AddStringToObject(new_cert, "issuer_o", "IoT Platform");
    cJSON_AddStringToObject(new_cert, "serial", serial ? serial : "");
    cJSON_AddStringToObject(new_cert, "fingerprint_sha256", fp ? fp : "");
    cJSON_AddStringToObject(new_cert, "algorithm", algo);
    cJSON_AddStringToObject(new_cert, "valid_from", ts);
    cJSON_AddStringToObject(new_cert, "valid_to", vt_ts);
    cJSON_AddStringToObject(new_cert, "status", "valid");
    cJSON_AddNullToObject(new_cert, "bound_to");
    cJSON_AddNullToObject(new_cert, "bound_at");
    cJSON_AddStringToObject(new_cert, "created_at", ts);
    cJSON_AddStringToObject(new_cert, "created_by", "superman");
    cJSON_AddNullToObject(new_cert, "revoked_at");
    cJSON_AddNullToObject(new_cert, "revoked_by");
    cJSON_AddNullToObject(new_cert, "revoke_reason");
    cJSON_AddItemToArray(certs, new_cert);

    /* 更新序号 */
    cJSON *seq = cJSON_GetObjectItem(root, "cert_sequence");
    if (seq) seq->valuedouble += 1;
    save_certs_json(root);

    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "id", uuid);
    cJSON_AddStringToObject(data, "name", name);
    free(fp); free(serial);
    cJSON_Delete(req); cJSON_Delete(root);
    plog("证书已创建: %s (id=%s, cn=%s)", name, uuid, cn);
    *out_status = 200;
    return create_response(0, "success", data);
}

/* ========== API: get_cert_detail ========== */
char* get_cert_detail(const char *data_json, int *out_status) {
    cJSON *req = cJSON_Parse(data_json);
    if (!req) { *out_status=400; return create_response(-1,"Invalid JSON",NULL); }
    cJSON *id_o = cJSON_GetObjectItem(req,"id");
    if (!id_o) { cJSON_Delete(req); *out_status=400; return create_response(-1,"Missing id",NULL); }

    cJSON *root = load_certs_json();
    cJSON *cert = find_cert(root, id_o->valuestring);
    if (!cert) { cJSON_Delete(req); cJSON_Delete(root); *out_status=404;
        return create_response(1005,"证书不存在",NULL); }

    cJSON *data = cJSON_Duplicate(cert, 1);
    /* 计算剩余天数 */
    cJSON *vt = cJSON_GetObjectItem(cert, "valid_to");
    if (vt) {
        struct tm tm={0}; int y,m,d; sscanf(vt->valuestring,"%d-%d-%dT",&y,&m,&d);
        time_t vt_t=mktime(&(struct tm){.tm_year=y-1900,.tm_mon=m-1,.tm_mday=d});
        int days = (vt_t-time(NULL))/86400;
        cJSON_AddNumberToObject(data, "days_remaining", days > 0 ? days : 0);
    }
    cJSON_AddStringToObject(data, "status_label", cert_status_label(cert));

    cJSON_Delete(req); cJSON_Delete(root);
    *out_status = 200;
    return create_response(0, "success", data);
}

/* ========== API: download_cert ========== */
char* download_cert(const char *data_json, int *out_status) {
    cJSON *req = cJSON_Parse(data_json);
    if (!req) { *out_status=400; return create_response(-1,"Invalid JSON",NULL); }
    cJSON *id_o = cJSON_GetObjectItem(req,"id");
    cJSON *fmt_o = cJSON_GetObjectItem(req,"format");
    const char *fmt = (fmt_o && cJSON_IsString(fmt_o)) ? fmt_o->valuestring : "pem";

    cJSON *root = load_certs_json();
    cJSON *cert = find_cert(root, id_o->valuestring);
    if (!cert) { cJSON_Delete(req); cJSON_Delete(root); *out_status=404;
        return create_response(1005,"证书不存在",NULL); }

    /* 校验证书状态 */
    if (!is_cert_valid(cert) && strcmp(fmt, "p12")==0) {
        cJSON_Delete(req); cJSON_Delete(root); *out_status=403;
        return create_response(1006,"证书已过期/吊销，不允许下载P12",NULL); }

    char cert_dir[256]; snprintf(cert_dir,sizeof(cert_dir),"/data/certs/certs/%s",id_o->valuestring);
    char *content = NULL;

    if (strcmp(fmt, "p12")==0) {
        /* 生成随机密码 */
        char pwd[16]; const char *cs="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$";
        for(int i=0;i<12;i++) pwd[i]=cs[rand()%strlen(cs)]; pwd[12]='\0';
        /* 重新生成P12 */
        char cmd[1024]; char p12_path[512]; snprintf(p12_path,sizeof(p12_path),"%s/cert.p12",cert_dir);
        snprintf(cmd,sizeof(cmd),"openssl pkcs12 -export -in %s/cert.crt -inkey %s/cert.key "
                 "-out %s -passout pass:%s 2>/dev/null", cert_dir, cert_dir, p12_path, pwd);
        system(cmd);
        long len=0; content=read_file(p12_path, &len);
        cJSON *data = cJSON_CreateObject();
        cJSON_AddStringToObject(data, "content", content ? content : "");
        cJSON_AddStringToObject(data, "password", pwd);
        cJSON_AddStringToObject(data, "format", "p12");
        cJSON_AddStringToObject(data, "filename", "cert.p12");
        if(content) free(content);
        cJSON_Delete(req); cJSON_Delete(root);
        *out_status = 200;
        return create_response(0, "success", data);
    } else {
        long len=0; char crt_path[512]; snprintf(crt_path,sizeof(crt_path),"%s/cert.crt",cert_dir);
        content=read_file(crt_path, &len);
        cJSON *data = cJSON_CreateObject();
        cJSON_AddStringToObject(data, "content", content ? content : "");
        cJSON_AddStringToObject(data, "format", "pem");
        cJSON_AddStringToObject(data, "filename", "cert.crt");
        if(content) free(content);
        cJSON_Delete(req); cJSON_Delete(root);
        *out_status = 200;
        return create_response(0, "success", data);
    }
}

/* ========== API: revoke_cert ========== */
char* revoke_cert(const char *data_json, int *out_status) {
    cJSON *req = cJSON_Parse(data_json);
    if (!req) { *out_status=400; return create_response(-1,"Invalid JSON",NULL); }
    cJSON *id_o = cJSON_GetObjectItem(req,"id");
    cJSON *reason_o = cJSON_GetObjectItem(req,"reason");
    const char *reason = (reason_o && cJSON_IsString(reason_o)) ? reason_o->valuestring : "";

    cJSON *root = load_certs_json();
    cJSON *cert = find_cert(root, id_o->valuestring);
    if (!cert) { cJSON_Delete(req); cJSON_Delete(root); *out_status=404;
        return create_response(1005,"证书不存在",NULL); }
    cJSON *st = cJSON_GetObjectItem(cert, "status");
    if (st && strcmp(st->valuestring,"revoked")==0) {
        cJSON_Delete(req); cJSON_Delete(root); *out_status=400;
        return create_response(1013,"证书已吊销",NULL); }

    cJSON_DeleteItemFromObject(cert, "status"); cJSON_AddStringToObject(cert, "status", "revoked");
    time_t now=time(NULL); char ts[64]; strftime(ts,sizeof(ts),"%Y-%m-%dT%H:%M:%SZ",gmtime(&now));
    cJSON_DeleteItemFromObject(cert, "revoked_at"); cJSON_AddStringToObject(cert, "revoked_at", ts);
    cJSON_DeleteItemFromObject(cert, "revoked_by"); cJSON_AddStringToObject(cert, "revoked_by", "superman");
    cJSON_DeleteItemFromObject(cert, "revoke_reason"); cJSON_AddStringToObject(cert, "revoke_reason", reason);
    save_certs_json(root);

    plog("证书已吊销: %s reason=%s", id_o->valuestring, reason);
    cJSON_Delete(req); cJSON_Delete(root);
    *out_status = 200; return create_response(0, "success", NULL);
}

/* ========== API: delete_cert ========== */
char* delete_cert(const char *data_json, int *out_status) {
    cJSON *req = cJSON_Parse(data_json);
    if (!req) { *out_status=400; return create_response(-1,"Invalid JSON",NULL); }
    cJSON *id_o = cJSON_GetObjectItem(req,"id");
    cJSON *root = load_certs_json();
    cJSON *certs = cJSON_GetObjectItem(root, "certs");
    cJSON *target=NULL; cJSON_ArrayForEach(target, certs) {
        cJSON *cid=cJSON_GetObjectItem(target,"id");
        if(cid && strcmp(cid->valuestring,id_o->valuestring)==0) break; }
    if(!target){cJSON_Delete(req);cJSON_Delete(root);*out_status=404;return create_response(1005,"证书不存在",NULL);}
    cJSON *st=cJSON_GetObjectItem(target,"status");
    if(st && strcmp(st->valuestring,"valid")==0){cJSON_Delete(req);cJSON_Delete(root);*out_status=400;
        return create_response(1012,"有效证书不允许删除",NULL);}

    cJSON_DeleteItemFromArray(certs, cJSON_GetArrayItem(certs, 0) == target ? 0 :
        (int)(target - cJSON_GetArrayItem(certs,0)) / sizeof(cJSON)); /* approximate removal */
    /* 从数组中移除 */
    { int found=-1, i=0; cJSON *it; cJSON_ArrayForEach(it,certs) {
        cJSON *ci=cJSON_GetObjectItem(it,"id");
        if(ci && strcmp(ci->valuestring,id_o->valuestring)==0){found=i;break;} i++; }
    if(found>=0) cJSON_DeleteItemFromArray(certs, found); }
    save_certs_json(root);

    /* 删除文件目录 */
    char cmd[512]; snprintf(cmd,sizeof(cmd),"rm -rf /data/certs/certs/%s",id_o->valuestring);
    system(cmd);

    plog("证书已删除: %s", id_o->valuestring);
    cJSON_Delete(req); cJSON_Delete(root);
    *out_status = 200; return create_response(0, "success", NULL);
}

/* ========== API: resend_cert_email ========== */
char* resend_cert_email(const char *data_json, int *out_status) {
    cJSON *req = cJSON_Parse(data_json);
    if (!req) { *out_status=400; return create_response(-1,"Invalid JSON",NULL); }
    cJSON *id_o = cJSON_GetObjectItem(req,"id");

    cJSON *root = load_certs_json();
    cJSON *cert = find_cert(root, id_o->valuestring);
    if (!cert) { cJSON_Delete(req); cJSON_Delete(root); *out_status=404;
        return create_response(1005,"证书不存在",NULL); }

    cJSON *bound = cJSON_GetObjectItem(cert, "bound_to");
    if (!bound || !cJSON_IsString(bound) || strlen(bound->valuestring)==0) {
        cJSON_Delete(req); cJSON_Delete(root); *out_status=400;
        return create_response(1011,"证书未绑定管理员",NULL); }

    plog("重发证书邮件: %s -> %s", id_o->valuestring, bound->valuestring);
    /* TODO: 调用邮件发送接口 */
    cJSON_Delete(req); cJSON_Delete(root);
    *out_status = 200; return create_response(0, "邮件已重新发送", NULL);
}

/* ========== 根证书初始化入口 ========== */
char* cert_init(const char *data_json, int *out_status) {
    (void)data_json;
    int ret = cert_init_root();
    *out_status = ret == 0 ? 200 : 500;
    return create_response(ret, ret==0 ? "根证书就绪" : "根证书初始化失败", NULL);
}
