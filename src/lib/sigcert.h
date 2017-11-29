#ifndef _FLUX_SIGCERT_H
#define _FLUX_SIGCERT_H

#include <stdbool.h>
#include <stdint.h>

/* Certificate class for signing/verification.
 *
 * Keys can be loaded/stored from TOML based certificate files.
 * The "secret" version of the certificate contains everything.
 * The "public" version of the certificate contains all but private keys.
 * The public version is distinguished by a .pub extension (like ssh keys).
 */

#ifdef __cplusplus
extern "C" {
#endif

struct flux_sigcert;

/* Destroy cert.
 */
void flux_sigcert_destroy (struct flux_sigcert *cert);

/* Create cert with new keys
 */
struct flux_sigcert *flux_sigcert_create (void);

/* Load cert from file 'name', falling back to 'name.pub'.
 */
struct flux_sigcert *flux_sigcert_load (const char *name);

/* Store cert to 'name' and 'name.pub'.
 */
int flux_sigcert_store (const struct flux_sigcert *cert, const char *name);

/* Decode JSON string to cert.
 */
struct flux_sigcert *flux_sigcert_json_loads (const char *s);

/* Encode public cert to JSON string.  Caller must free.
 */
char *flux_sigcert_json_dumps (const struct flux_sigcert *cert);

/* Return true if two certificates have the same keys.
 */
bool flux_sigcert_equal (const struct flux_sigcert *cert1,
                         const struct flux_sigcert *cert2);

/* Return a detached signature (base64 string) over buf, len.
 * Caller must free.
 */
char *flux_sigcert_sign (const struct flux_sigcert *cert,
                         uint8_t *buf, int len);

/* Verify a detached signature (base64 string) over buf, len.
 * Returns 0 on success, -1 on failure.
 */
int flux_sigcert_verify (const struct flux_sigcert *cert,
                         const char *signature, uint8_t *buf, int len);


/* Get/set metadata
 */
int flux_sigcert_meta_sets (struct flux_sigcert *cert,
                            const char *key, const char *value);
int flux_sigcert_meta_gets (const struct flux_sigcert *cert,
                            const char *key, const char **value);
int flux_sigcert_meta_seti (struct flux_sigcert *cert,
                            const char *key, int64_t value);
int flux_sigcert_meta_geti (const struct flux_sigcert *cert,
                            const char *key, int64_t *value);
int flux_sigcert_meta_setd (struct flux_sigcert *cert,
                            const char *key, double value);
int flux_sigcert_meta_getd (const struct flux_sigcert *cert,
                            const char *key, double *value);
int flux_sigcert_meta_setb (struct flux_sigcert *cert,
                            const char *key, bool value);
int flux_sigcert_meta_getb (const struct flux_sigcert *cert,
                            const char *key, bool *value);

#ifdef __cplusplus
}
#endif

#endif /* !_FLUX_SIGCERT_H */

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
