#ifndef EMAIL_H
#define EMAIL_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the email library by loading configuration.
 * @param config_path  Path to the INI configuration file.
 * @return 0 on success, -1 on failure.
 */
int email_init(const char *config_path);

/**
 * @brief Send a verification code email.
 * @param email  Recipient email address.
 * @param code   Verification code string.
 * @return 0 on success, -1 on parameter error, -2 on timeout,
 *         -3 on API error, -4 on config error.
 */
int email_send_code(const char *to, const char *username, const char *code);

/**
 * @brief Release resources held by the email library.
 */
void email_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* EMAIL_H */
