#ifndef TOTP_H
#define TOTP_H
#ifdef __cplusplus
extern "C" {
#endif
int totp_init(const char *config_path);
int totp_verify(const char *secret_base32, const char *code);
int totp_generate_secret(char *out_base32, size_t out_len);
void totp_cleanup(void);
#ifdef __cplusplus
}
#endif
#endif
