#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <ctype.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <cjson/cJSON.h>

#include "totp.h"

/* ────────────────────────────────────────────
 * Configuration defaults (TOTP RFC 6238)
 * ──────────────────────────────────────────── */
#define TOTP_TIME_STEP  30
#define TOTP_DIGITS     6
#define TOTP_WINDOW     1       /* +/- 1 interval for clock skew */

/* ────────────────────────────────────────────
 * Base32 alphabet (RFC 4648, uppercase)
 * ──────────────────────────────────────────── */
static const char B32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/* ────────────────────────────────────────────
 * Internal state (loaded from config)
 * ──────────────────────────────────────────── */
static int g_time_step = TOTP_TIME_STEP;
static int g_digits    = TOTP_DIGITS;

/* ────────────────────────────────────────────
 * totp_init  –  load optional config
 * ──────────────────────────────────────────── */
int totp_init(const char *config_path)
{
    const char *path = config_path ? config_path : "/etc/auth_config.json";
    int time_step = TOTP_TIME_STEP;
    int digits    = TOTP_DIGITS;

    FILE *fp = fopen(path, "r");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        long fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        if (fsize <= 0) { fclose(fp); fp = NULL; /* skip to defaults */ }
        else {
        char *content = (char *)malloc((size_t)fsize + 1);
        if (content) {
            size_t nread = fread(content, 1, (size_t)fsize, fp);
            content[nread] = '\0';

            cJSON *root = cJSON_Parse(content);
            if (root) {
                cJSON *channels = cJSON_GetObjectItem(root, "channels");
                if (channels) {
                    cJSON *totp = cJSON_GetObjectItem(channels, "totp");
                    if (totp) {
                        cJSON *ts = cJSON_GetObjectItem(totp, "time_step");
                        if (ts && cJSON_IsNumber(ts))
                            time_step = ts->valueint;

                        cJSON *dig = cJSON_GetObjectItem(totp, "digits");
                        if (dig && cJSON_IsNumber(dig))
                            digits = dig->valueint;
                    }
                }
                cJSON_Delete(root);
            }
            free(content);
        }
        } /* end else (fsize > 0) */
        fclose(fp);
    }

    /* sanity checks */
    if (time_step < 1)   time_step = TOTP_TIME_STEP;
    if (digits < 6)      digits    = TOTP_DIGITS;
    if (digits < 1 || digits > 9)  digits = TOTP_DIGITS;  /* totp_divisor 仅支持 1-9 位 */

    g_time_step = time_step;
    g_digits    = digits;

    return 0;
}

/* ────────────────────────────────────────────
 * Power-of-10 table for modulo (avoids pow())
 * ──────────────────────────────────────────── */
static unsigned int totp_divisor(int digits)
{
    static const unsigned int table[] = {
        1, 10, 100, 1000, 10000, 100000,
        1000000, 10000000, 100000000, 1000000000U
    };
    if (digits < 1 || digits > 9) return 1000000U;
    return table[digits];
}

/* ────────────────────────────────────────────
 * Base32 decode  –  returns decoded length, -1 on error
 * Handles both padded ('=') and unpadded input.
 * ──────────────────────────────────────────── */
static int base32_decode(const char *input, unsigned char *output, size_t out_max)
{
    size_t inlen = strlen(input);
    size_t outlen = 0;
    int bits = 0;
    unsigned int buffer = 0;

    for (size_t i = 0; i < inlen; i++) {
        char c = input[i];

        /* skip padding */
        if (c == '=')
            break;

        /* upper-case for matching */
        if (c >= 'a' && c <= 'z')
            c = (char)(c - 'a' + 'A');

        /* find index in alphabet */
        const char *pos = strchr(B32_ALPHABET, c);
        if (!pos)
            return -1;  /* invalid character */
        unsigned int val = (unsigned int)(pos - B32_ALPHABET);

        buffer = (buffer << 5) | val;
        bits += 5;

        if (bits >= 8) {
            bits -= 8;
            if (outlen >= out_max) return -1;
            output[outlen++] = (unsigned char)(buffer >> bits);
            buffer &= ((1U << bits) - 1);
        }
    }

    return (int)outlen;
}

/* ────────────────────────────────────────────
 * Base32 encode
 * ──────────────────────────────────────────── */
static int base32_encode(const unsigned char *input, size_t inlen,
                          char *output, size_t out_max)
{
    size_t outlen = 0;
    int bits = 0;
    unsigned int buffer = 0;

    for (size_t i = 0; i < inlen; i++) {
        buffer = (buffer << 8) | input[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            if (outlen >= out_max) return -1;
            output[outlen++] = B32_ALPHABET[(buffer >> bits) & 0x1F];
        }
    }

    /* remaining bits */
    if (bits > 0) {
        if (outlen >= out_max) return -1;
        output[outlen++] = B32_ALPHABET[(buffer << (5 - bits)) & 0x1F];
    }

    /* always null-terminate if possible */
    if (outlen < out_max)
        output[outlen] = '\0';

    return (int)outlen;
}

/* ────────────────────────────────────────────
 * Constant-time comparison  –  avoids timing side-channels
 * ──────────────────────────────────────────── */
static int const_time_compare(const unsigned char *a, const char *b, size_t len)
{
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (unsigned char)(a[i] ^ (unsigned char)b[i]);
    }
    /* diff will be 0 iff every byte matched */
    return (diff == 0) ? 0 : -5;
}

/* ────────────────────────────────────────────
 * totp_verify  –  verify a 6-digit (or N-digit) TOTP code
 *
 * Returns:  0  – success
 *          -5  – verification failed
 *          -1  – parameter error
 * ──────────────────────────────────────────── */
int totp_verify(const char *secret_base32, const char *code)
{
    if (!secret_base32 || !code)
        return -1;

    int codelen = (int)strlen(code);
    if (codelen != g_digits)
        return -1;

    /* ── 1. Decode Base32 secret ── */
    unsigned char key[64];
    int keylen = base32_decode(secret_base32, key, sizeof(key));
    if (keylen <= 0)
        return -1;

    /* ── 2. Compute counter = unix_time / time_step ── */
    uint64_t counter = (uint64_t)time(NULL) / (uint64_t)g_time_step;

    /* ── 3. Allow ±TOTP_WINDOW intervals ── */
    int64_t start = (int64_t)counter - TOTP_WINDOW;
    int64_t end   = (int64_t)counter + TOTP_WINDOW;
    if (start < 0) start = 0;

    for (int64_t c = start; c <= end; c++) {
        /* ── 3a. Convert counter to 8-byte big-endian ── */
        unsigned char counter_bytes[8];
        uint64_t val = (uint64_t)c;
        for (int i = 7; i >= 0; i--) {
            counter_bytes[i] = (unsigned char)(val & 0xFF);
            val >>= 8;
        }

        /* ── 3b. HMAC-SHA1 ── */
        unsigned char hmac_result[EVP_MAX_MD_SIZE];
        unsigned int hmac_len = 0;
        unsigned char *hmac = HMAC(EVP_sha1(),
                                   key, keylen,
                                   counter_bytes, sizeof(counter_bytes),
                                   hmac_result, &hmac_len);
        if (!hmac)
            return -1;

        /* ── 3c. Dynamic truncation ── */
        unsigned char offset = hmac[hmac_len - 1] & 0x0F;
        if (offset + 4 > hmac_len)
            return -1;

        unsigned int binary =
            ((unsigned int)(hmac[offset]     & 0x7F) << 24) |
            ((unsigned int)(hmac[offset + 1] & 0xFF) << 16) |
            ((unsigned int)(hmac[offset + 2] & 0xFF) <<  8) |
            ((unsigned int)(hmac[offset + 3] & 0xFF));

        /* ── 3d. Modulo 10^digits ── */
        unsigned int otp = binary % totp_divisor(g_digits);

        /* ── 3e. Format code as zero-padded string for comparison ── */
        char otp_str[16];
        snprintf(otp_str, sizeof(otp_str), "%0*u", g_digits, otp);

        /* ── 3f. Constant-time comparison ── */
        if (const_time_compare((const unsigned char *)otp_str, code, (size_t)g_digits) == 0)
            return 0;
    }

    return -5;  /* no matching window */
}

/* ────────────────────────────────────────────
 * totp_generate_secret  –  random 20-byte key as Base32
 *
 * Returns: 0 on success, -1 on error.
 * ──────────────────────────────────────────── */
int totp_generate_secret(char *out_base32, size_t out_len)
{
    if (!out_base32 || out_len < 33)  /* 32 chars + null */
        return -1;

    unsigned char raw[20];
    if (RAND_bytes(raw, sizeof(raw)) != 1)
        return -1;

    if (base32_encode(raw, sizeof(raw), out_base32, out_len) < 0)
        return -1;

    return 0;
}

/* ────────────────────────────────────────────
 * totp_cleanup  –  no-op (reserved for future use)
 * ──────────────────────────────────────────── */
void totp_cleanup(void)
{
    /* nothing to release currently */
}
