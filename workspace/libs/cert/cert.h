#ifndef CERT_H
#define CERT_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Load configuration from /etc/cert_config.ini and initialize OpenSSL.
 * Returns 0 on success, -1 on error.
 */
int cert_init(const char *config_path);

/**
 * Compare two SHA-256 hex fingerprint strings using constant-time comparison.
 * Returns 0 on match, -5 on mismatch, -1 on parameter error.
 */
int cert_verify_fingerprint(const char *stored_fingerprint_hex,
                            const char *provided_fingerprint_hex);

/* Unified interface: cert_verify(target, code) — alias for cert_verify_fingerprint */
int cert_verify(const char *stored_fingerprint_hex, const char *provided_fingerprint_hex);

/**
 * Parse a PEM-encoded X.509 certificate and extract its SHA-256 fingerprint
 * as a hex string (64 characters + null terminator).
 * Returns 0 on success, -1 on parse error.
 */
int cert_parse_pem_extract_fingerprint(const char *pem_data, size_t pem_len,
                                       char *out_fingerprint_hex, size_t out_len);

/**
 * Parse a PEM certificate and check if the current time falls between
 * valid_from and valid_to (ISO8601 format: "2026-01-01T00:00:00Z").
 * Also checks the certificate's internal NotBefore/NotAfter fields.
 * Returns 0 if valid, -5 if expired or not yet valid, -1 on error.
 */
int cert_check_validity(const char *pem_data, size_t pem_len,
                        const char *valid_from, const char *valid_to);

/**
 * Cleanup resources. Currently a no-op (OpenSSL cleanup handled by caller).
 */
void cert_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* CERT_H */
