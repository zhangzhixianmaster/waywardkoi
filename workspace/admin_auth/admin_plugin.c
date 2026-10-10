/*
 * 管理员 CRUD 插件 - 完整版
 * 支持: 密码策略校验、手机/邮箱/TOTP/证书字段、密码历史、弱密码拦截、策略管理
 * 编译: gcc -shared -o libadmin.so admin_plugin.c -fPIC -Wall -O2 -lcjson -lcrypto
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <cjson/cJSON.h>

/* Compatibility: older cJSON versions may lack cJSON_IsTrue */
#ifndef cJSON_IsTrue
#define cJSON_IsTrue(x) ((x) && (x)->type == cJSON_True)
#endif


#define ADMINS_FILE       "/data/admins.json"
#define AUTH_CONFIG_FILE  "/etc/auth_config.json"

typedef struct {
    int id;
    char username[64];
    char password[128];
    char password_history[8][128];  /* 最多8条历史密码哈希 */
    int history_count;
    char phone[32];
    char email[96];
    char role[32];
    char created_at[64];
    char totp_secret[64];
    int  totp_enabled;
    char cert_fingerprint[96];
    char cert_serial[32];
    char cert_valid_from[32];
    char cert_valid_to[32];
} Admin;

/* ==================== 弱密码字典（100+条） ==================== */
static const char *common_passwords[] = {
    "123456","password","12345678","qwerty","123456789",
    "12345","1234","111111","1234567","dragon",
    "123123","baseball","abc123","football","monkey",
    "letmein","shadow","master","666666","qwertyuiop",
    "123321","mustang","1234567890","michael","654321",
    "superman","1qaz2wsx","7777777","121212","000000",
    "qazwsx","123qwe","killer","trustno1","jordan",
    "jennifer","zxcvbnm","asdfgh","hunter","buster",
    "soccer","harley","batman","andrew","tigger",
    "sunshine","iloveyou","2000","charlie","robert",
    "thomas","hockey","ranger","daniel","starwars",
    "klaster","112233","george","computer","michelle",
    "jessica","pepper","zxcvbn","555555","11111111",
    "131313","freedom","777777","pass","maggie",
    "159753","ginger","princess","tigger","cheese",
    "amanda","summer","love","ashley","nicole",
    "chelsea","biteme","matthew","access","yankees",
    "987654321","dallas","austin","thunder","taylor",
    "matrix","mobilemail","mom","monitor","monitoring",
    "montana","moon","moscow","p@ssw0rd","Pa$$w0rd",
    "passw0rd","admin","Admin123","qwerty123","abc123456",
    "admin123","letmein1","welcome","welcome1","changeme",
    "Password1","p@ssword","pass123","Passw0rd","Qwerty123!",
    NULL
};

/* 前向声明 */
static void create_default_admin(cJSON *arr);
static void save_admins(cJSON *arr);

/* ==================== 文件操作 ==================== */
static cJSON* read_admins(void) {
    FILE *fp = fopen(ADMINS_FILE, "r");
    if (!fp) {
        cJSON *arr = cJSON_CreateArray();
        create_default_admin(arr);
        save_admins(arr);
        return arr;
    }
    fseek(fp, 0, SEEK_END); long fsize = ftell(fp); fseek(fp, 0, SEEK_SET);
    if (fsize <= 0) { fclose(fp);
        cJSON *arr = cJSON_CreateArray();
        create_default_admin(arr); save_admins(arr); return arr;
    }
    char *content = malloc(fsize + 1);
    if (!content) { fclose(fp);
        cJSON *arr = cJSON_CreateArray();
        create_default_admin(arr); save_admins(arr); return arr;
    }
    size_t nread = fread(content, 1, fsize, fp); fclose(fp);
    content[nread] = '\0';  /* 使用实际读取长度，而非 ftell 值 */
    cJSON *arr = cJSON_Parse(content); free(content);
    if (!arr) { arr = cJSON_CreateArray(); }
    if (cJSON_GetArraySize(arr) == 0) { create_default_admin(arr); save_admins(arr); }
    return arr;
}

/* 手机号脱敏 */
static void mask_phone(const char *phone, char *out, size_t out_size) {
    if (!phone || strlen(phone) == 0) { out[0] = '\0'; return; }
    size_t len = strlen(phone);
    const char *local = phone;
    if (len > 3 && phone[0] == '+') { local = phone + 3; len -= 3; }
    if (len >= 7) snprintf(out, out_size, "%.3s****%.4s", local, local + len - 4);
    else snprintf(out, out_size, "%s", phone);
}

static void create_default_admin(cJSON *arr) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)"passwd", 6, hash);
    char hash_str[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) sprintf(hash_str + i * 2, "%02x", hash[i]);

    cJSON *admin = cJSON_CreateObject();
    cJSON_AddNumberToObject(admin, "id", 1);
    cJSON_AddStringToObject(admin, "username", "superman");
    cJSON_AddStringToObject(admin, "password", hash_str);
    cJSON_AddItemToObject(admin, "password_history", cJSON_CreateArray());
    cJSON_AddStringToObject(admin, "role", "admin");
    cJSON_AddStringToObject(admin, "phone", "");
    cJSON_AddStringToObject(admin, "email", "");
    cJSON_AddStringToObject(admin, "totp_secret", "");
    cJSON_AddBoolToObject(admin, "totp_enabled", 0);
    cJSON_AddStringToObject(admin, "cert_fingerprint", "");
    cJSON_AddStringToObject(admin, "cert_serial", "");
    cJSON_AddStringToObject(admin, "cert_valid_from", "");
    cJSON_AddStringToObject(admin, "cert_valid_to", "");
    cJSON_AddStringToObject(admin, "created_at", "2025-01-01T00:00:00Z");
    cJSON_AddItemToArray(arr, admin);
}

static void save_admins(cJSON *arr) {
    mkdir("/data", 0755);
    char *str = cJSON_Print(arr);
    if (!str) return;  /* cJSON_Print OOM：放弃写入，避免清空原文件 */

    /* 原子写入：先写临时文件，再 rename */
    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", ADMINS_FILE);
    FILE *fp = fopen(tmp_path, "w");
    if (!fp) { free(str); return; }
    fprintf(fp, "%s", str);
    fflush(fp);
    fclose(fp);
    free(str);

    if (rename(tmp_path, ADMINS_FILE) != 0) {
        /* rename 失败：保留临时文件用于恢复 */
        fprintf(stderr, "[admin_plugin] rename(%s, %s) failed, tmp file kept\n", tmp_path, ADMINS_FILE);
    }
}

static void hash_password(const char *password, char *out) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, strlen(password), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) sprintf(out + i * 2, "%02x", hash[i]);
}

static char* create_response(int code, const char *message, cJSON *data) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "code", code);
    cJSON_AddStringToObject(obj, "message", message);
    if (data) cJSON_AddItemToObject(obj, "data", data);
    else cJSON_AddNullToObject(obj, "data");
    char *str = cJSON_Print(obj);
    cJSON_Delete(obj);
    return str;
}

/* ==================== 密码策略校验 ==================== */
typedef struct {
    int min_length;
    int require_uppercase;
    int require_lowercase;
    int require_digit;
    int require_special;
    int forbid_username;
    int forbid_common;
    int history_count;
} PwPolicy;

static void load_pw_policy(PwPolicy *pp) {
    memset(pp, 0, sizeof(PwPolicy));
    pp->min_length = 8;

    FILE *fp = fopen(AUTH_CONFIG_FILE, "r");
    if (!fp) return;
    fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
    if (sz <= 0) { fclose(fp); return; }
    char *buf = malloc(sz + 1);
    if (!buf) { fclose(fp); return; }
    size_t nread = fread(buf, 1, sz, fp); fclose(fp);
    buf[nread] = '\0';
    cJSON *root = cJSON_Parse(buf); free(buf);
    if (!root) return;

    cJSON *pp_obj = cJSON_GetObjectItem(root, "password_policy");
    if (pp_obj) {
        cJSON *v;
        v = cJSON_GetObjectItem(pp_obj, "min_length"); if (v) pp->min_length = (int)v->valuedouble;
        v = cJSON_GetObjectItem(pp_obj, "require_uppercase"); if (v) pp->require_uppercase = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp_obj, "require_lowercase"); if (v) pp->require_lowercase = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp_obj, "require_digit"); if (v) pp->require_digit = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp_obj, "require_special"); if (v) pp->require_special = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp_obj, "forbid_username"); if (v) pp->forbid_username = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp_obj, "forbid_common"); if (v) pp->forbid_common = cJSON_IsTrue(v);
        v = cJSON_GetObjectItem(pp_obj, "history_count"); if (v) pp->history_count = (int)v->valuedouble;
    }
    cJSON_Delete(root);
}

/* 返回: 0=通过, -1=太短, -2=缺大写, -3=缺小写, -4=缺数字, -5=缺特殊字符,
         -6=包含用户名, -7=弱密码, -8=与历史密码重复 */
static int validate_password(const char *password, const char *username, PwPolicy *pp,
                             cJSON *history_arr) {
    int len = (int)strlen(password);
    if (len < pp->min_length) return -1;

    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
    for (int i = 0; i < len; i++) {
        if (isupper((unsigned char)password[i])) has_upper = 1;
        else if (islower((unsigned char)password[i])) has_lower = 1;
        else if (isdigit((unsigned char)password[i])) has_digit = 1;
        else has_special = 1;
    }
    if (pp->require_uppercase && !has_upper) return -2;
    if (pp->require_lowercase && !has_lower) return -3;
    if (pp->require_digit && !has_digit) return -4;
    if (pp->require_special && !has_special) return -5;

    /* 检查是否包含用户名（大小写不敏感） */
    if (pp->forbid_username && username && strlen(username) > 0) {
        char *pw_lower = strdup(password);
        char *un_lower = strdup(username);
        if (pw_lower && un_lower) {
            for (int i = 0; pw_lower[i]; i++) pw_lower[i] = tolower((unsigned char)pw_lower[i]);
            for (int i = 0; un_lower[i]; i++) un_lower[i] = tolower((unsigned char)un_lower[i]);
            if (strstr(pw_lower, un_lower)) { free(pw_lower); free(un_lower); return -6; }
        }
        free(pw_lower); free(un_lower);
    }

    /* 检查弱密码字典 */
    if (pp->forbid_common) {
        for (int i = 0; common_passwords[i]; i++) {
            if (strcasecmp(password, common_passwords[i]) == 0) return -7;
        }
    }

    /* 检查密码历史 */
    if (pp->history_count > 0 && history_arr) {
        char hashed[65]; hash_password(password, hashed);
        int arr_size = cJSON_GetArraySize(history_arr);
        int check_count = arr_size < pp->history_count ? arr_size : pp->history_count;
        cJSON *item;
        int idx = 0;
        cJSON_ArrayForEach(item, history_arr) {
            if (idx >= check_count) break;
            if (cJSON_IsString(item) && strcmp(item->valuestring, hashed) == 0) return -8;
            idx++;
        }
    }

    return 0;
}

static const char* pw_error_msg(int code) {
    switch (code) {
        case -1: return "密码长度不足";
        case -2: return "密码需包含大写字母";
        case -3: return "密码需包含小写字母";
        case -4: return "密码需包含数字";
        case -5: return "密码需包含特殊字符";
        case -6: return "密码不能包含用户名";
        case -7: return "密码过于常见，请更换";
        case -8: return "密码与历史密码重复";
        default: return "未知错误";
    }
}

/* ==================== 管理员 CRUD ==================== */

char* admin_create(const char *data_json, int *out_status) {
    cJSON *data = cJSON_Parse(data_json);
    if (!data) { *out_status = 400; return create_response(-1, "Invalid JSON data", NULL); }

    cJSON *username_obj = cJSON_GetObjectItem(data, "username");
    cJSON *password_obj = cJSON_GetObjectItem(data, "password");
    if (!username_obj || !cJSON_IsString(username_obj) ||
        !password_obj || !cJSON_IsString(password_obj)) {
        cJSON_Delete(data); *out_status = 400;
        return create_response(-1, "Missing username or password", NULL);
    }

    const char *username = username_obj->valuestring;
    const char *password = password_obj->valuestring;
    cJSON *role_obj = cJSON_GetObjectItem(data, "role");
    const char *role = (role_obj && cJSON_IsString(role_obj)) ? role_obj->valuestring : "operator";
    cJSON *phone_obj = cJSON_GetObjectItem(data, "phone");
    const char *phone = (phone_obj && cJSON_IsString(phone_obj)) ? phone_obj->valuestring : "";
    cJSON *email_obj = cJSON_GetObjectItem(data, "email");
    const char *email = (email_obj && cJSON_IsString(email_obj)) ? email_obj->valuestring : "";

    /* 密码策略校验 */
    PwPolicy pp; load_pw_policy(&pp);
    int pw_ret = validate_password(password, username, &pp, NULL);
    if (pw_ret != 0) {
        cJSON_Delete(data); *out_status = 400;
        return create_response(pw_ret, pw_error_msg(pw_ret), NULL);
    }

    cJSON *admins = read_admins();

    /* 检查用户名唯一性 */
    cJSON *item;
    cJSON_ArrayForEach(item, admins) {
        cJSON *u = cJSON_GetObjectItem(item, "username");
        if (u && strcmp(u->valuestring, username) == 0) {
            cJSON_Delete(admins); cJSON_Delete(data); *out_status = 400;
            return create_response(-100, "Username already exists", NULL);
        }
    }
    /* 检查手机号唯一性 */
    if (strlen(phone) > 0) {
        cJSON_ArrayForEach(item, admins) {
            cJSON *p = cJSON_GetObjectItem(item, "phone");
            if (p && cJSON_IsString(p) && strlen(p->valuestring) > 0 && strcmp(p->valuestring, phone) == 0) {
                cJSON_Delete(admins); cJSON_Delete(data); *out_status = 400;
                return create_response(-103, "Phone number already bound", NULL);
            }
        }
    }
    /* 检查邮箱唯一性 */
    if (strlen(email) > 0) {
        cJSON_ArrayForEach(item, admins) {
            cJSON *e = cJSON_GetObjectItem(item, "email");
            if (e && cJSON_IsString(e) && strlen(e->valuestring) > 0 && strcmp(e->valuestring, email) == 0) {
                cJSON_Delete(admins); cJSON_Delete(data); *out_status = 400;
                return create_response(-104, "Email already bound", NULL);
            }
        }
    }

    /* 生成新ID */
    int max_id = 0;
    cJSON_ArrayForEach(item, admins) {
        cJSON *id_obj = cJSON_GetObjectItem(item, "id");
        if (id_obj && id_obj->valuedouble > max_id) max_id = (int)id_obj->valuedouble;
    }

    char hashed[65]; hash_password(password, hashed);
    time_t now = time(NULL);
    struct tm gm_tm;
    char time_str[64]; strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", gmtime_r(&now, &gm_tm));

    cJSON *new_admin = cJSON_CreateObject();
    cJSON_AddNumberToObject(new_admin, "id", max_id + 1);
    cJSON_AddStringToObject(new_admin, "username", username);
    cJSON_AddStringToObject(new_admin, "password", hashed);
    cJSON_AddItemToObject(new_admin, "password_history", cJSON_CreateArray());
    cJSON_AddStringToObject(new_admin, "role", role);
    cJSON_AddStringToObject(new_admin, "phone", phone);
    cJSON_AddStringToObject(new_admin, "email", email);
    cJSON_AddStringToObject(new_admin, "totp_secret", "");
    cJSON_AddBoolToObject(new_admin, "totp_enabled", 0);
    cJSON_AddStringToObject(new_admin, "cert_fingerprint", "");
    cJSON_AddStringToObject(new_admin, "cert_serial", "");
    cJSON_AddStringToObject(new_admin, "cert_valid_from", "");
    cJSON_AddStringToObject(new_admin, "cert_valid_to", "");
    cJSON_AddNullToObject(new_admin, "cert_id");
    cJSON_AddNullToObject(new_admin, "cert_bound_at");
    cJSON_AddStringToObject(new_admin, "created_at", time_str);
    cJSON_AddItemToArray(admins, new_admin);
    save_admins(admins);

    cJSON *resp_data = cJSON_CreateObject();
    cJSON_AddNumberToObject(resp_data, "id", max_id + 1);
    cJSON_Delete(admins); cJSON_Delete(data);
    *out_status = 200;
    return create_response(0, "success", resp_data);
}

char* admin_read(const char *data_json, int *out_status) {
    cJSON *admins = read_admins();
    cJSON *safe_list = cJSON_CreateArray();

    cJSON *item;
    cJSON_ArrayForEach(item, admins) {
        cJSON *safe = cJSON_CreateObject();
        cJSON *id = cJSON_GetObjectItem(item, "id");
        cJSON *user = cJSON_GetObjectItem(item, "username");
        cJSON *role = cJSON_GetObjectItem(item, "role");
        cJSON *created = cJSON_GetObjectItem(item, "created_at");
        cJSON *phone = cJSON_GetObjectItem(item, "phone");
        cJSON *email_o = cJSON_GetObjectItem(item, "email");
        cJSON *totp_e = cJSON_GetObjectItem(item, "totp_enabled");
        cJSON *cert_fp = cJSON_GetObjectItem(item, "cert_fingerprint");
        cJSON *cert_id = cJSON_GetObjectItem(item, "cert_id");

        if (id) cJSON_AddNumberToObject(safe, "id", id->valuedouble);
        if (user) cJSON_AddStringToObject(safe, "username", user->valuestring);
        if (role) cJSON_AddStringToObject(safe, "role", role->valuestring);

        /* 手机号脱敏 */
        if (phone && cJSON_IsString(phone)) {
            char masked[32]; mask_phone(phone->valuestring, masked, sizeof(masked));
            cJSON_AddStringToObject(safe, "phone", masked);
        } else cJSON_AddStringToObject(safe, "phone", "");

        if (email_o) cJSON_AddStringToObject(safe, "email", email_o->valuestring);
        else cJSON_AddStringToObject(safe, "email", "");

        /* 直接检查类型和值，兼容不同 cJSON 版本 */
        {
            int te_val = 0;
            if (totp_e) {
                if (totp_e->type == cJSON_True) te_val = 1;
                else if (cJSON_IsTrue(totp_e)) te_val = 1;
                else if (totp_e->valueint) te_val = 1;
            }
            cJSON_AddBoolToObject(safe, "totp_enabled", te_val);
        }

        if (cert_fp && cJSON_IsString(cert_fp) && strlen(cert_fp->valuestring) > 0)
            cJSON_AddStringToObject(safe, "cert_fingerprint", cert_fp->valuestring);
        else cJSON_AddStringToObject(safe, "cert_fingerprint", "");
        if (cert_id && cJSON_IsString(cert_id) && strlen(cert_id->valuestring) > 0)
            cJSON_AddStringToObject(safe, "cert_id", cert_id->valuestring);
        else cJSON_AddNullToObject(safe, "cert_id");

        if (created) cJSON_AddStringToObject(safe, "created_at", created->valuestring);
        cJSON_AddItemToArray(safe_list, safe);
    }

    cJSON *resp_data = cJSON_CreateObject();
    cJSON_AddItemToObject(resp_data, "admins", safe_list);
    cJSON_Delete(admins);
    *out_status = 200;
    return create_response(0, "success", resp_data);
}

/* ==================== 单个管理员详情 ==================== */
char* admin_get(const char *data_json, int *out_status) {
    cJSON *data = cJSON_Parse(data_json);
    if (!data) { *out_status = 400; return create_response(-1, "Invalid JSON", NULL); }
    cJSON *id_obj = cJSON_GetObjectItem(data, "id");
    cJSON *name_obj = cJSON_GetObjectItem(data, "username");
    cJSON *admins = read_admins();
    cJSON *target = NULL, *item;
    cJSON_ArrayForEach(item, admins) {
        if (id_obj && cJSON_IsNumber(id_obj)) {
            cJSON *id = cJSON_GetObjectItem(item, "id");
            if (id && (int)id->valuedouble == (int)id_obj->valuedouble) { target = item; break; }
        } else if (name_obj && cJSON_IsString(name_obj)) {
            cJSON *u = cJSON_GetObjectItem(item, "username");
            if (u && cJSON_IsString(u) && strcmp(u->valuestring, name_obj->valuestring) == 0) { target = item; break; }
        }
    }
    if (!target) { cJSON_Delete(admins); cJSON_Delete(data); *out_status = 404;
        return create_response(-101, "Admin not found", NULL); }
    /* 调试日志 */
    {
        cJSON *te = cJSON_GetObjectItem(target, "totp_enabled");
        cJSON *ts = cJSON_GetObjectItem(target, "totp_secret");
        fprintf(stderr, "[ADMIN_GET] totp_enabled_type=%d totp_secret=%s\n",
            te ? te->type : -1, (ts && cJSON_IsString(ts)) ? ts->valuestring : "NULL");
    }
    cJSON *resp_data = cJSON_Duplicate(target, 1);
    cJSON_Delete(admins); cJSON_Delete(data);
    *out_status = 200;
    return create_response(0, "success", resp_data);
}

char* admin_update(const char *data_json, int *out_status) {
    cJSON *data = cJSON_Parse(data_json);
    if (!data) { *out_status = 400; return create_response(-1, "Invalid JSON data", NULL); }

    cJSON *id_obj = cJSON_GetObjectItem(data, "id");
    if (!id_obj || !cJSON_IsNumber(id_obj)) {
        cJSON_Delete(data); *out_status = 400;
        return create_response(-1, "Missing id", NULL);
    }
    int admin_id = (int)id_obj->valuedouble;

    cJSON *admins = read_admins();
    cJSON *target = NULL;
    cJSON *item;
    cJSON_ArrayForEach(item, admins) {
        cJSON *id = cJSON_GetObjectItem(item, "id");
        if (id && (int)id->valuedouble == admin_id) { target = item; break; }
    }
    if (!target) { cJSON_Delete(admins); cJSON_Delete(data); *out_status = 404;
        return create_response(-101, "Admin not found", NULL); }

    /* 更新用户名 */
    cJSON *username_obj = cJSON_GetObjectItem(data, "username");
    if (username_obj && cJSON_IsString(username_obj)) {
        cJSON *other;
        cJSON_ArrayForEach(other, admins) {
            if (other == target) continue;
            cJSON *u = cJSON_GetObjectItem(other, "username");
            if (u && strcmp(u->valuestring, username_obj->valuestring) == 0) {
                cJSON_Delete(admins); cJSON_Delete(data); *out_status = 400;
                return create_response(-100, "Username already exists", NULL);
            }
        }
        cJSON_DeleteItemFromObject(target, "username");
        cJSON_AddStringToObject(target, "username", username_obj->valuestring);
    }

    /* 更新密码（含策略校验+历史管理） */
    cJSON *password_obj = cJSON_GetObjectItem(data, "password");
    if (password_obj && cJSON_IsString(password_obj)) {
        const char *new_pw = password_obj->valuestring;
        const char *uname = NULL;
        cJSON *u = cJSON_GetObjectItem(target, "username");
        if (u) uname = u->valuestring;

        cJSON *history_arr = cJSON_GetObjectItem(target, "password_history");
        if (!history_arr) {
            history_arr = cJSON_CreateArray();
            cJSON_AddItemToObject(target, "password_history", history_arr);
        }

        PwPolicy pp; load_pw_policy(&pp);
        int pw_ret = validate_password(new_pw, uname, &pp, history_arr);
        if (pw_ret != 0) {
            cJSON_Delete(admins); cJSON_Delete(data); *out_status = 400;
            return create_response(pw_ret, pw_error_msg(pw_ret), NULL);
        }

        /* 保存旧密码到历史 */
        cJSON *old_pw = cJSON_GetObjectItem(target, "password");
        if (old_pw && cJSON_IsString(old_pw) && strlen(old_pw->valuestring) > 0) {
            cJSON_AddItemToArray(history_arr, cJSON_CreateString(old_pw->valuestring));
            /* 限制历史条数 */
            while (cJSON_GetArraySize(history_arr) > (pp.history_count > 0 ? pp.history_count : 8)) {
                cJSON_DeleteItemFromArray(history_arr, 0);
            }
        }

        char hashed[65]; hash_password(new_pw, hashed);
        cJSON_DeleteItemFromObject(target, "password");
        cJSON_AddStringToObject(target, "password", hashed);
    }

    /* 更新角色 */
    cJSON *role_obj = cJSON_GetObjectItem(data, "role");
    if (role_obj && cJSON_IsString(role_obj)) {
        cJSON_DeleteItemFromObject(target, "role");
        cJSON_AddStringToObject(target, "role", role_obj->valuestring);
    }

    /* 更新手机号 */
    cJSON *phone_obj = cJSON_GetObjectItem(data, "phone");
    if (phone_obj && cJSON_IsString(phone_obj)) {
        const char *np = phone_obj->valuestring;
        if (strlen(np) > 0) {
            cJSON *other;
            cJSON_ArrayForEach(other, admins) {
                if (other == target) continue;
                cJSON *p = cJSON_GetObjectItem(other, "phone");
                if (p && cJSON_IsString(p) && strlen(p->valuestring) > 0 && strcmp(p->valuestring, np) == 0) {
                    cJSON_Delete(admins); cJSON_Delete(data); *out_status = 400;
                    return create_response(-103, "Phone already bound", NULL);
                }
            }
        }
        cJSON_DeleteItemFromObject(target, "phone");
        cJSON_AddStringToObject(target, "phone", np);
    }

    /* 更新邮箱 */
    cJSON *email_obj = cJSON_GetObjectItem(data, "email");
    if (email_obj && cJSON_IsString(email_obj)) {
        const char *ne = email_obj->valuestring;
        if (strlen(ne) > 0) {
            cJSON *other;
            cJSON_ArrayForEach(other, admins) {
                if (other == target) continue;
                cJSON *e = cJSON_GetObjectItem(other, "email");
                if (e && cJSON_IsString(e) && strlen(e->valuestring) > 0 && strcmp(e->valuestring, ne) == 0) {
                    cJSON_Delete(admins); cJSON_Delete(data); *out_status = 400;
                    return create_response(-104, "Email already bound", NULL);
                }
            }
        }
        cJSON_DeleteItemFromObject(target, "email");
        cJSON_AddStringToObject(target, "email", ne);
    }

    /* 更新 TOTP */
    cJSON *totp_secret_obj = cJSON_GetObjectItem(data, "totp_secret");
    if (totp_secret_obj && cJSON_IsString(totp_secret_obj)) {
        cJSON_DeleteItemFromObject(target, "totp_secret");
        cJSON_AddStringToObject(target, "totp_secret", totp_secret_obj->valuestring);
    }
    cJSON *totp_enabled_obj = cJSON_GetObjectItem(data, "totp_enabled");
    if (totp_enabled_obj) {
        cJSON_DeleteItemFromObject(target, "totp_enabled");
        cJSON_AddBoolToObject(target, "totp_enabled", cJSON_IsTrue(totp_enabled_obj));
    }

    /* 更新 certificate_id（绑定证书） */
    cJSON *cert_id_obj = cJSON_GetObjectItem(data, "cert_id");
    if (cert_id_obj) {
        fprintf(stderr, "[CERT_BIND] admin_update cert_id=%s\n",
                cJSON_IsString(cert_id_obj) ? cert_id_obj->valuestring : "NULL");
        /* 释放旧证书 */
        cJSON *old_id = cJSON_GetObjectItem(target, "cert_id");
        if (old_id && cJSON_IsString(old_id) && strlen(old_id->valuestring) > 0) {
            /* 在 certs.json 中释放 */
            FILE *cf = fopen("/data/certs/certs.json", "r");
            if (cf) { fseek(cf,0,SEEK_END); long sz=ftell(cf); fseek(cf,0,SEEK_SET);
                if(sz>0){ char *cb=malloc(sz+1); if(cb){ fread(cb,1,sz,cf); cb[sz]='\0';
                    cJSON *cr=cJSON_Parse(cb); free(cb);
                    if(cr){ cJSON *ca=cJSON_GetObjectItem(cr,"certs"); cJSON *it;
                        cJSON_ArrayForEach(it,ca){ cJSON *ci=cJSON_GetObjectItem(it,"id");
                            if(ci&&strcmp(ci->valuestring,old_id->valuestring)==0){
                                cJSON_DeleteItemFromObject(it,"bound_to"); cJSON_AddNullToObject(it,"bound_to");
                                cJSON_DeleteItemFromObject(it,"bound_at"); cJSON_AddNullToObject(it,"bound_at");
                                break; } }
                        char *ns=cJSON_Print(cr); if(ns){ fclose(cf); cf=fopen("/data/certs/certs.json","w");
                            if(cf){ fprintf(cf,"%s",ns); fclose(cf); } free(ns); }
                        else fclose(cf);
                        cJSON_Delete(cr); } } } else fclose(cf);
            }
        }
        /* 设置新绑定 */
        cJSON_DeleteItemFromObject(target, "cert_id");
        cJSON_DeleteItemFromObject(target, "cert_bound_at");
        if (cJSON_IsString(cert_id_obj) && strlen(cert_id_obj->valuestring) > 0) {
            cJSON_AddStringToObject(target, "cert_id", cert_id_obj->valuestring);
            time_t now = time(NULL); struct tm gm_tm; char ts[64];
            strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmtime_r(&now, &gm_tm));
            cJSON_AddStringToObject(target, "cert_bound_at", ts);
            /* 更新 certs.json 的 bound_to */
            FILE *cf = fopen("/data/certs/certs.json", "r");
            if (cf) { fseek(cf,0,SEEK_END); long sz=ftell(cf); fseek(cf,0,SEEK_SET);
                if(sz>0){ char *cb=malloc(sz+1); if(cb){ fread(cb,1,sz,cf); cb[sz]='\0';
                    cJSON *cr=cJSON_Parse(cb); free(cb);
                    if(cr){ cJSON *ca=cJSON_GetObjectItem(cr,"certs"); cJSON *it;
                        cJSON_ArrayForEach(it,ca){ cJSON *ci=cJSON_GetObjectItem(it,"id");
                            if(ci&&strcmp(ci->valuestring,cert_id_obj->valuestring)==0){
                                cJSON *uname=cJSON_GetObjectItem(target,"username");
                                cJSON_DeleteItemFromObject(it,"bound_to");
                                cJSON_AddStringToObject(it,"bound_to",uname?uname->valuestring:"");
                                cJSON_DeleteItemFromObject(it,"bound_at");
                                { time_t n2=time(NULL); struct tm g2; char ts2[64];
                                  strftime(ts2,sizeof(ts2),"%Y-%m-%dT%H:%M:%SZ",gmtime_r(&n2,&g2));
                                  cJSON_AddStringToObject(it,"bound_at",ts2); }
                                break; } }
                        char *ns=cJSON_Print(cr); if(ns){ fclose(cf); cf=fopen("/data/certs/certs.json","w");
                            if(cf){ fprintf(cf,"%s",ns); fclose(cf); } free(ns); }
                        else fclose(cf);
                        cJSON_Delete(cr); } } } else fclose(cf);
        } else {
            fprintf(stderr, "[CERT_UNBIND] admin_update clearing cert_id\n");
            cJSON_AddNullToObject(target, "cert_id");
            cJSON_AddNullToObject(target, "cert_bound_at");
        }
    }

    /* 更新证书字段（直接指纹） */
    cJSON *cert_fp = cJSON_GetObjectItem(data, "cert_fingerprint");
    if (cert_fp && cJSON_IsString(cert_fp)) {
        cJSON_DeleteItemFromObject(target, "cert_fingerprint");
        cJSON_AddStringToObject(target, "cert_fingerprint", cert_fp->valuestring);
    }
    cJSON *cert_ser = cJSON_GetObjectItem(data, "cert_serial");
    if (cert_ser && cJSON_IsString(cert_ser)) {
        cJSON_DeleteItemFromObject(target, "cert_serial");
        cJSON_AddStringToObject(target, "cert_serial", cert_ser->valuestring);
    }
    cJSON *cert_vf = cJSON_GetObjectItem(data, "cert_valid_from");
    if (cert_vf && cJSON_IsString(cert_vf)) {
        cJSON_DeleteItemFromObject(target, "cert_valid_from");
        cJSON_AddStringToObject(target, "cert_valid_from", cert_vf->valuestring);
    }
    cJSON *cert_vt = cJSON_GetObjectItem(data, "cert_valid_to");
    if (cert_vt && cJSON_IsString(cert_vt)) {
        cJSON_DeleteItemFromObject(target, "cert_valid_to");
        cJSON_AddStringToObject(target, "cert_valid_to", cert_vt->valuestring);
    }

    save_admins(admins);
    cJSON_Delete(admins); cJSON_Delete(data);
    *out_status = 200;
    return create_response(0, "success", NULL);
}
}
char* admin_delete(const char *data_json, int *out_status) {
    cJSON *data = cJSON_Parse(data_json);
    if (!data) { *out_status = 400; return create_response(-1, "Invalid JSON data", NULL); }

    cJSON *id_obj = cJSON_GetObjectItem(data, "id");
    if (!id_obj || !cJSON_IsNumber(id_obj)) {
        cJSON_Delete(data); *out_status = 400;
        return create_response(-1, "Missing id", NULL);
    }
    int admin_id = (int)id_obj->valuedouble;

    cJSON *admins = read_admins();
    int idx = 0, found = -1;
    cJSON *item;
    cJSON_ArrayForEach(item, admins) {
        cJSON *id = cJSON_GetObjectItem(item, "id");
        if (id && (int)id->valuedouble == admin_id) { found = idx; break; }
        idx++;
    }
    if (found == -1) { cJSON_Delete(admins); cJSON_Delete(data); *out_status = 404;
        return create_response(-101, "Admin not found", NULL); }

    /* 预置管理员（id=1, username=superman）不可删除 */
    cJSON *found_item = cJSON_GetArrayItem(admins, found);
    cJSON *found_id = cJSON_GetObjectItem(found_item, "id");
    cJSON *found_uname = cJSON_GetObjectItem(found_item, "username");
    if ((found_id && (int)found_id->valuedouble == 1) ||
        (found_uname && cJSON_IsString(found_uname) && strcmp(found_uname->valuestring, "superman") == 0)) {
        cJSON_Delete(admins); cJSON_Delete(data); *out_status = 403;
        return create_response(-105, "Cannot delete the preset super admin", NULL);
    }

    /* 检查不能删除最后一个超级管理员 */
    cJSON *role_obj = cJSON_GetObjectItem(found_item, "role");
    if (role_obj && strcmp(role_obj->valuestring, "admin") == 0) {
        int admin_count = 0;
        cJSON *child;
        cJSON_ArrayForEach(child, admins) {
            cJSON *r = cJSON_GetObjectItem(child, "role");
            if (r && strcmp(r->valuestring, "admin") == 0) admin_count++;
        }
        if (admin_count <= 1) {
            cJSON_Delete(admins); cJSON_Delete(data); *out_status = 403;
            return create_response(-102, "Cannot delete the last super admin", NULL);
        }
    }

    cJSON *new_arr = cJSON_CreateArray();
    int ni = 0;
    cJSON_ArrayForEach(item, admins) {
        if (ni != found) cJSON_AddItemToArray(new_arr, cJSON_Duplicate(item, 1));
        ni++;
    }
    /* 先保存再释放旧数据，避免写入失败导致数据丢失 */
    save_admins(new_arr);
    cJSON_Delete(admins);
    cJSON_Delete(new_arr); cJSON_Delete(data);
    *out_status = 200;
    return create_response(0, "success", NULL);
}

/* ==================== 认证策略管理 ==================== */
char* admin_update_auth_policy(const char *data_json, int *out_status) {
    cJSON *data = cJSON_Parse(data_json);
    if (!data) { *out_status = 400; return create_response(-1, "Invalid JSON data", NULL); }

    /* 读取当前策略 */
    cJSON *policy = cJSON_CreateObject();
    FILE *fp = fopen(AUTH_CONFIG_FILE, "r");
    if (fp) {
        fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
        if (sz > 0) {
            char *buf = malloc(sz + 1);
            if (buf) {
                size_t nread = fread(buf, 1, sz, fp); buf[nread] = '\0';
                cJSON *old = cJSON_Parse(buf);
                if (old) { cJSON_Delete(policy); policy = old; }
                free(buf);
            }
        }
        fclose(fp);
    }

    /* 更新 login_policy */
    cJSON *lp = cJSON_GetObjectItem(data, "login_policy");
    if (lp && cJSON_IsString(lp)) {
        cJSON_DeleteItemFromObject(policy, "login_policy");
        cJSON_AddStringToObject(policy, "login_policy", lp->valuestring);
    }

    /* 更新 password_policy */
    cJSON *pp = cJSON_GetObjectItem(data, "password_policy");
    if (pp) {
        cJSON *existing = cJSON_GetObjectItem(policy, "password_policy");
        if (!existing) { existing = cJSON_CreateObject(); cJSON_AddItemToObject(policy, "password_policy", existing); }

        cJSON *v;
        v = cJSON_GetObjectItem(pp, "min_length"); if (v) { cJSON_DeleteItemFromObject(existing, "min_length"); cJSON_AddNumberToObject(existing, "min_length", v->valuedouble); }
        v = cJSON_GetObjectItem(pp, "require_uppercase"); if (v) { cJSON_DeleteItemFromObject(existing, "require_uppercase"); cJSON_AddBoolToObject(existing, "require_uppercase", cJSON_IsTrue(v)); }
        v = cJSON_GetObjectItem(pp, "require_lowercase"); if (v) { cJSON_DeleteItemFromObject(existing, "require_lowercase"); cJSON_AddBoolToObject(existing, "require_lowercase", cJSON_IsTrue(v)); }
        v = cJSON_GetObjectItem(pp, "require_digit"); if (v) { cJSON_DeleteItemFromObject(existing, "require_digit"); cJSON_AddBoolToObject(existing, "require_digit", cJSON_IsTrue(v)); }
        v = cJSON_GetObjectItem(pp, "require_special"); if (v) { cJSON_DeleteItemFromObject(existing, "require_special"); cJSON_AddBoolToObject(existing, "require_special", cJSON_IsTrue(v)); }
        v = cJSON_GetObjectItem(pp, "forbid_username"); if (v) { cJSON_DeleteItemFromObject(existing, "forbid_username"); cJSON_AddBoolToObject(existing, "forbid_username", cJSON_IsTrue(v)); }
        v = cJSON_GetObjectItem(pp, "forbid_common"); if (v) { cJSON_DeleteItemFromObject(existing, "forbid_common"); cJSON_AddBoolToObject(existing, "forbid_common", cJSON_IsTrue(v)); }
        v = cJSON_GetObjectItem(pp, "history_count"); if (v) { cJSON_DeleteItemFromObject(existing, "history_count"); cJSON_AddNumberToObject(existing, "history_count", v->valuedouble); }
    }

    /* 更新时间戳 */
    cJSON_DeleteItemFromObject(policy, "updated_at");
    time_t now = time(NULL);
    char ts[64]; strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    cJSON_AddStringToObject(policy, "updated_at", ts);

    cJSON *ub = cJSON_GetObjectItem(data, "updated_by");
    if (ub) { cJSON_DeleteItemFromObject(policy, "updated_by"); cJSON_AddNumberToObject(policy, "updated_by", ub->valuedouble); }

    /* 保存到统一配置文件 */
    mkdir("/etc", 0755);
    fp = fopen(AUTH_CONFIG_FILE, "w");
    if (!fp) { cJSON_Delete(policy); cJSON_Delete(data); *out_status = 500;
        return create_response(-1, "Cannot write config file", NULL); }
    char *str = cJSON_Print(policy);
    if (str) { fprintf(fp, "%s", str); free(str); }
    fclose(fp);
    cJSON_Delete(policy); cJSON_Delete(data);

    *out_status = 200;
    return create_response(0, "success", NULL);
}

/* ==================== TOTP 绑定辅助 ==================== */
/*
 * action=totp_generate: 为指定管理员生成 TOTP 密钥
 * 请求: { "id": 1 }
 * 响应: { "totp_secret": "JBSWY3DPEHPK3PXP", "totp_uri": "otpauth://totp/..." }
 */
char* admin_totp_generate(const char *data_json, int *out_status) {
    cJSON *data = cJSON_Parse(data_json);
    if (!data) { *out_status = 400; return create_response(-1, "Invalid JSON data", NULL); }

    /* 生成 TOTP 密钥 */
    char secret[33];
    const char *b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    unsigned char rb[32];
    if (RAND_bytes(rb, sizeof(rb)) != 1) {
        unsigned int seed = ((unsigned int)time(NULL) * 1103515245 + 12345);
        for (int i = 0; i < 32; i++) { seed = seed * 1103515245 + 12345; rb[i] = (unsigned char)(seed >> 16); }
    }
    for (int i = 0; i < 32; i++) secret[i] = b32[rb[i] % 32];
    secret[32] = '\0';

    char username_buf[64] = "admin";
    /* 请求参数优先（新建时），其次从已有管理员 JSON（编辑时） */
    cJSON *req_user = cJSON_GetObjectItem(data, "username");
    if (req_user && cJSON_IsString(req_user))
        strncpy(username_buf, req_user->valuestring, sizeof(username_buf)-1);

    cJSON *id_obj = cJSON_GetObjectItem(data, "id");
    if (id_obj) {
        /* 有 id：为已有管理员生成并保存 */
        int admin_id = (int)id_obj->valuedouble;
        cJSON *admins = read_admins();
        cJSON *target = NULL, *item;
        cJSON_ArrayForEach(item, admins) {
            cJSON *id = cJSON_GetObjectItem(item, "id");
            if (id && (int)id->valuedouble == admin_id) { target = item; break; }
        }
        if (!target) { cJSON_Delete(admins); cJSON_Delete(data); *out_status = 404;
            return create_response(-101, "Admin not found", NULL); }
        /* 复制用户名（在释放 JSON 之前）*/
        cJSON *u = cJSON_GetObjectItem(target, "username");
        if (u && cJSON_IsString(u))
            strncpy(username_buf, u->valuestring, sizeof(username_buf)-1);

        cJSON_DeleteItemFromObject(target, "totp_secret");
        cJSON_AddStringToObject(target, "totp_secret", secret);
        cJSON_DeleteItemFromObject(target, "totp_enabled");
        cJSON_AddBoolToObject(target, "totp_enabled", 1);
        save_admins(admins);
        cJSON_Delete(admins);
    }
    /* 无 id：仅生成密钥返回，不保存到任何管理员 */
    cJSON_Delete(data);

    /* URL 编码用户名 */
    char encoded_user[128]; int ej = 0;
    for (const char *c = username_buf; *c && ej < (int)sizeof(encoded_user) - 4; c++) {
        unsigned char uc = (unsigned char)*c;
        if ((uc >= 'A' && uc <= 'Z') || (uc >= 'a' && uc <= 'z') || (uc >= '0' && uc <= '9')
            || uc == '-' || uc == '_' || uc == '.' || uc == '~') {
            encoded_user[ej++] = (char)uc;
        } else if (uc == ' ') {
            encoded_user[ej++] = '%'; encoded_user[ej++] = '2'; encoded_user[ej++] = '0';
        } else {
            encoded_user[ej++] = '%';
            encoded_user[ej++] = "0123456789ABCDEF"[uc >> 4];
            encoded_user[ej++] = "0123456789ABCDEF"[uc & 0xF];
        }
    }
    encoded_user[ej] = '\0';

    /* 读取 TOTP 配置参数 */
    char issuer[64] = "IoT Platform";
    int digits = 6, period = 30;
    {
        FILE *fp = fopen(AUTH_CONFIG_FILE, "r");
        if (fp) {
            fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
            if (sz > 0) {
                char *buf = malloc(sz + 1);
                if (buf) {
                    size_t n = fread(buf, 1, sz, fp); buf[n] = '\0';
                    cJSON *root = cJSON_Parse(buf); free(buf);
                    if (root) {
                        cJSON *chs = cJSON_GetObjectItem(root, "channels");
                        if (chs) {
                            cJSON *totp = cJSON_GetObjectItem(chs, "totp");
                            if (totp) {
                                cJSON *v;
                                v = cJSON_GetObjectItem(totp, "issuer");
                                if (v && cJSON_IsString(v)) strncpy(issuer, v->valuestring, sizeof(issuer)-1);
                                v = cJSON_GetObjectItem(totp, "digits");
                                if (v && cJSON_IsNumber(v)) digits = (int)v->valuedouble;
                                v = cJSON_GetObjectItem(totp, "time_step");
                                if (v && cJSON_IsNumber(v)) period = (int)v->valuedouble;
                            }
                        }
                        cJSON_Delete(root);
                    }
                }
            }
            fclose(fp);
        }
    }

    /* URL 编码 issuer */
    char enc_issuer[128]; int ej2 = 0;
    for (const char *c = issuer; *c && ej2 < (int)sizeof(enc_issuer) - 4; c++) {
        unsigned char uc = (unsigned char)*c;
        if ((uc >= 'A' && uc <= 'Z') || (uc >= 'a' && uc <= 'z') || (uc >= '0' && uc <= '9')
            || uc == '-' || uc == '_' || uc == '.' || uc == '~') enc_issuer[ej2++] = (char)uc;
        else if (uc == ' ') { enc_issuer[ej2++] = '%'; enc_issuer[ej2++] = '2'; enc_issuer[ej2++] = '0'; }
        else { enc_issuer[ej2++] = '%';
               enc_issuer[ej2++] = "0123456789ABCDEF"[uc >> 4];
               enc_issuer[ej2++] = "0123456789ABCDEF"[uc & 0xF]; }
    }
    enc_issuer[ej2] = '\0';

    /* 构建 URI: otpauth://totp/Issuer:User?secret=XXX&issuer=Issuer&digits=6&period=30 */
    char uri[512];
    snprintf(uri, sizeof(uri),
             "otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
             enc_issuer, encoded_user, secret, enc_issuer, digits, period);

    cJSON *resp_data = cJSON_CreateObject();
    cJSON_AddStringToObject(resp_data, "totp_secret", secret);
    cJSON_AddStringToObject(resp_data, "totp_uri", uri);

    *out_status = 200;
    return create_response(0, "success", resp_data);
}

/* ==================== 操作日志查询 ==================== */
/*
 * action=log_query: 查询操作审计日志
 * 请求: { "limit": 50 }
 * 响应: { "logs": [{ "time","user","action","ip","success" }] }
 *
 * 日志文件路径: /var/log/work_log/auth_audit.log
 * 格式: 每行一条 JSON
 */
char* admin_log_query(const char *data_json, int *out_status) {
    int limit = 50;
    cJSON *data = cJSON_Parse(data_json);
    if (data) {
        cJSON *lim = cJSON_GetObjectItem(data, "limit");
        if (lim) limit = (int)lim->valuedouble;
        cJSON_Delete(data);
    }
    if (limit <= 0) limit = 50;
    if (limit > 500) limit = 500;

    cJSON *logs_arr = cJSON_CreateArray();
    FILE *fp = fopen("/var/log/work_log/auth_audit.log", "r");
    if (fp) {
        char line[1024];
        char **lines = NULL;
        int total = 0;
        while (fgets(line, sizeof(line), fp) && total < 10000) {
            size_t l = strlen(line);
            if (l > 0 && line[l-1] == '\n') line[l-1] = '\0';
            if (l > 0 && line[l-1] == '\r') line[l-1] = '\0';
            if (strlen(line) == 0) continue;
            char **tmp = realloc(lines, (total + 1) * sizeof(char*));
            if (!tmp) break;
            lines = tmp;
            lines[total] = strdup(line);
            if (lines[total]) total++;
        }
        fclose(fp);

        int start = total > limit ? total - limit : 0;
        for (int i = start; i < total; i++) {
            cJSON *entry = cJSON_Parse(lines[i]);
            if (entry) cJSON_AddItemToArray(logs_arr, entry);
            free(lines[i]);
        }
        free(lines);
    }

    cJSON *resp_data = cJSON_CreateObject();
    cJSON_AddItemToObject(resp_data, "logs", logs_arr);
    *out_status = 200;
    return create_response(0, "success", resp_data);
}
