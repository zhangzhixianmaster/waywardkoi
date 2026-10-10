#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <cjson/cJSON.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "cert.h"

/* ------------------------------------------------------------------------- */
/*  Configuration state                                                       */
/* ------------------------------------------------------------------------- */

static char  g_ca_cert_path[512] = {0};
static char  g_crl_path[512]      = {0};
static int   g_require_crl        = 0;

/* ------------------------------------------------------------------------- */
/*  Helper: hex char to nibble                                                */
/* ------------------------------------------------------------------------- */

static int hex_char_to_nibble(char c, unsigned char *out)
{
    if (c >= '0' && c <= '9') { *out = (unsigned char)(c - '0'); return 1; }
    if (c >= 'a' && c <= 'f') { *out = (unsigned char)(c - 'a' + 10); return 1; }
    if (c >= 'A' && c <= 'F') { *out = (unsigned char)(c - 'A' + 10); return 1; }
    return 0;
}

/* ------------------------------------------------------------------------- */
/*  Helper: hex string to raw bytes                                           */
/*  Returns byte count on success, -1 on error.                               */
/* ------------------------------------------------------------------------- */

static int hex_to_bytes(const char *hex, unsigned char *buf, size_t buf_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;

    size_t byte_count = hex_len / 2;
    if (byte_count > buf_len) return -1;

    for (size_t i = 0; i < byte_count; i++) {
        unsigned char hi, lo;
        if (!hex_char_to_nibble(hex[2 * i], &hi)) return -1;
        if (!hex_char_to_nibble(hex[2 * i + 1], &lo)) return -1;
        buf[i] = (unsigned char)((hi << 4) | lo);
    }
    return (int)byte_count;
}

/* ------------------------------------------------------------------------- */
/*  Helper: constant-time memory comparison (returns 0 on match)              */
/* ------------------------------------------------------------------------- */

static int const_time_memcmp(const unsigned char *a, const unsigned char *b,
                             size_t len)
{
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    /* Force the result to be 0 or 1 to avoid leaking the diff value */
    return (diff != 0) ? 1 : 0;
}

/* ------------------------------------------------------------------------- */
/*  Helper: parse ISO8601 date string "YYYY-MM-DDThh:mm:ssZ" to time_t       */
/*  Returns 0 on success, -1 on error.                                       */
/* ------------------------------------------------------------------------- */

static int parse_iso8601_to_time_t(const char *iso_str, time_t *out_time)
{
    struct tm tm_val;
    memset(&tm_val, 0, sizeof(tm_val));

    /* Expected format: "2026-01-01T00:00:00Z" */
    int year, month, day, hour, min, sec;
    if (sscanf(iso_str, "%4d-%2d-%2dT%2d:%2d:%2dZ",
               &year, &month, &day, &hour, &min, &sec) != 6) {
        return -1;
    }

    tm_val.tm_year = year - 1900;
    tm_val.tm_mon  = month - 1;
    tm_val.tm_mday = day;
    tm_val.tm_hour = hour;
    tm_val.tm_min  = min;
    tm_val.tm_sec  = sec;
    tm_val.tm_isdst = 0;

    /* timegm is not standard; use mktime on POSIX and adjust for UTC.
     * For simplicity we use _mkgmtime on Windows or timegm on Linux.
     * A portable approach: assume input is UTC and use a manual calculation,
     * or use the non-portable but common timegm.  We guard with ifdefs. */
#if defined(_WIN32)
    *out_time = _mkgmtime(&tm_val);
#else
    *out_time = timegm(&tm_val);
#endif

    if (*out_time == (time_t)-1) return -1;
    return 0;
}

/* ------------------------------------------------------------------------- */
/*  Helper: parse a simple INI config file                                    */
/* ------------------------------------------------------------------------- */

static int parse_json_config(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "cert_init: cannot open config file '%s'\n", path);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0) {
        fclose(fp);
        fprintf(stderr, "cert_init: empty or invalid config file '%s'\n", path);
        return -1;
    }

    char *content = (char *)malloc((size_t)fsize + 1);
    if (!content) {
        fclose(fp);
        return -1;
    }

    size_t nread = fread(content, 1, (size_t)fsize, fp);
    content[nread] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(content);
    free(content);

    if (!root) {
        fprintf(stderr, "cert_init: failed to parse JSON config '%s'\n", path);
        return -1;
    }

    cJSON *channels = cJSON_GetObjectItem(root, "channels");
    if (channels) {
        cJSON *cert = cJSON_GetObjectItem(channels, "cert");
        if (cert) {
            cJSON *item;

            item = cJSON_GetObjectItem(cert, "ca_cert_path");
            if (item && cJSON_IsString(item))
                strncpy(g_ca_cert_path, item->valuestring, sizeof(g_ca_cert_path) - 1);

            item = cJSON_GetObjectItem(cert, "crl_path");
            if (item && cJSON_IsString(item))
                strncpy(g_crl_path, item->valuestring, sizeof(g_crl_path) - 1);

            item = cJSON_GetObjectItem(cert, "require_crl");
            if (item)
                g_require_crl = cJSON_IsTrue(item) ? 1 : 0;
        }
    }

    /* Apply defaults for any fields not set in the JSON */
    if (g_ca_cert_path[0] == '\0')
        strncpy(g_ca_cert_path, "/etc/ssl/certs/ca.pem", sizeof(g_ca_cert_path) - 1);
    if (g_crl_path[0] == '\0')
        strncpy(g_crl_path, "/etc/ssl/crl/ca.crl", sizeof(g_crl_path) - 1);

    cJSON_Delete(root);
    return 0;
}

/* ------------------------------------------------------------------------- */
/*  Public API                                                                */
/* ------------------------------------------------------------------------- */

int cert_init(const char *config_path)
{
    const char *path = config_path ? config_path : "/etc/auth_config.json";

    /* Parse configuration file (JSON format) */
    if (parse_json_config(path) != 0) {
        return -1;
    }

    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    return 0;
}

int cert_verify_fingerprint(const char *stored_fingerprint_hex,
                            const char *provided_fingerprint_hex)
{
    if (!stored_fingerprint_hex || !provided_fingerprint_hex) {
        return -1;
    }

    /* SHA-256 produces 32 bytes -> 64 hex chars */
    size_t stored_len  = strlen(stored_fingerprint_hex);
    size_t prov_len    = strlen(provided_fingerprint_hex);

    if (stored_len != 64 || prov_len != 64) {
        return -1;
    }

    /* Decode hex strings to binary for constant-time comparison */
    unsigned char stored_bytes[32];
    unsigned char provided_bytes[32];

    if (hex_to_bytes(stored_fingerprint_hex, stored_bytes, sizeof(stored_bytes)) < 0) {
        return -1;
    }
    if (hex_to_bytes(provided_fingerprint_hex, provided_bytes, sizeof(provided_bytes)) < 0) {
        return -1;
    }

    if (const_time_memcmp(stored_bytes, provided_bytes, 32) != 0) {
        return -5; /* mismatch */
    }

    return 0; /* match */
}

/* Unified interface alias: cert_verify(target_fingerprint, provided_fingerprint) */
int cert_verify(const char *stored_fingerprint_hex, const char *provided_fingerprint_hex) {
    return cert_verify_fingerprint(stored_fingerprint_hex, provided_fingerprint_hex);
}

int cert_parse_pem_extract_fingerprint(const char *pem_data, size_t pem_len,
                                       char *out_fingerprint_hex, size_t out_len)
{
    /* Parameter validation */
    if (!pem_data || pem_len == 0 || !out_fingerprint_hex || out_len < 65) {
        return -1;
    }

    /* Create a BIO from the PEM data */
    BIO *bio = BIO_new_mem_buf(pem_data, (int)pem_len);
    if (!bio) {
        return -1;
    }

    /* Parse the PEM certificate */
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!cert) {
        return -1;
    }

    /* Compute SHA-256 fingerprint using OpenSSL EVP functions */
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  digest_len = 0;

    if (X509_digest(cert, EVP_sha256(), digest, &digest_len) != 1) {
        X509_free(cert);
        return -1;
    }

    X509_free(cert);

    /* SHA-256 digest is always 32 bytes */
    if (digest_len != 32) {
        return -1;
    }

    /* Convert to hex string */
    for (unsigned int i = 0; i < digest_len; i++) {
        snprintf(out_fingerprint_hex + (i * 2), 3, "%02x", digest[i]);
    }
    out_fingerprint_hex[64] = '\0';

    return 0;
}

int cert_check_validity(const char *pem_data, size_t pem_len,
                        const char *valid_from, const char *valid_to)
{
    /* Parameter validation */
    if (!pem_data || pem_len == 0 || !valid_from || !valid_to) {
        return -1;
    }

    /* Parse caller-provided date range */
    time_t from_time, to_time;
    if (parse_iso8601_to_time_t(valid_from, &from_time) != 0) return -1;
    if (parse_iso8601_to_time_t(valid_to, &to_time) != 0) return -1;

    /* Get current time */
    time_t now = time(NULL);

    /* Check against caller-provided validity window */
    if (now < from_time || now > to_time) {
        return -5; /* expired or not yet valid */
    }

    /* Check the certificate's internal NotBefore / NotAfter */
    BIO *bio = BIO_new_mem_buf(pem_data, (int)pem_len);
    if (!bio) return -1;

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!cert) return -1;

    /* Get NotBefore */
    const ASN1_TIME *not_before = X509_get0_notBefore(cert);
    const ASN1_TIME *not_after  = X509_get0_notAfter(cert);

    if (!not_before || !not_after) {
        X509_free(cert);
        return -1;
    }

    /* Compare current time against cert validity period.
     * X509_cmp_time returns:
     *   -1  if the time is before the cert time
     *    0  if the time equals the cert time
     *    1  if the time is after the cert time
     *
     * For NotBefore: cert is valid if current time >= notBefore  (result 0 or 1)
     * For NotAfter:  cert is valid if current time <= notAfter   (result -1 or 0)
     */
    int cmp_not_before = X509_cmp_time(not_before, &now);
    int cmp_not_after  = X509_cmp_time(not_after, &now);

    X509_free(cert);

    if (cmp_not_before < 0) {
        /* now is before notBefore -> cert not yet valid */
        return -5;
    }
    if (cmp_not_after > 0) {
        /* now is after notAfter -> cert expired */
        return -5;
    }

    return 0;
}

void cert_cleanup(void)
{
    /* No-op: OpenSSL cleanup is handled by the caller.
     * In a library context, calling OPENSSL_cleanup() or similar
     * could interfere with other users of OpenSSL in the same process. */
}
