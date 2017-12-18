#ifndef _UTIL_SIGCERT_H
#define _UTIL_SIGCERT_H

#include <time.h>
#include <stdbool.h>
#include <stdint.h>

/* Certificate class for signing/verification.
 *
 * Keys can be loaded/stored from TOML based certificate files.
 * The "secret" file only contains the secret-key.
 * The "public" file contains the public-key, metadata and signature.
 * The public version is distinguished by a .pub extension (like ssh keys).
 */

#ifdef __cplusplus
extern "C" {
#endif

struct sigcert;

/* Destroy cert.
 */
void sigcert_destroy (struct sigcert *cert);

/* Create cert with new keys
 */
struct sigcert *sigcert_create (void);

/* Load cert from file 'name.pub'.
 * If secret=true, load secret-key from 'name' also.
 */
struct sigcert *sigcert_load (const char *name, bool secret);

/* Store cert to 'name' and 'name.pub'.
 */
int sigcert_store (const struct sigcert *cert, const char *name);

/* Decode JSON string to cert.
 */
struct sigcert *sigcert_json_loads (const char *s);

/* Encode public cert to JSON string.  Caller must free.
 */
char *sigcert_json_dumps (const struct sigcert *cert);

/* Return true if two certificates have the same keys.
 */
bool sigcert_equal (const struct sigcert *cert1,
                    const struct sigcert *cert2);

/* Return a detached signature (base64 string) over buf, len.
 * Caller must free.
 */
char *sigcert_sign (const struct sigcert *cert,
                    uint8_t *buf, int len);

/* Verify a detached signature (base64 string) over buf, len.
 * Returns 0 on success, -1 on failure.
 */
int sigcert_verify (const struct sigcert *cert,
                    const char *signature, uint8_t *buf, int len);

/* Use cert1 to sign cert2.
 * The signature covers public key and all metadata.
 * It does not cover secret key or existing signature, if any.
 * The signature is embedded in cert2.
 */
int sigcert_sign_cert (const struct sigcert *cert1,
                       struct sigcert *cert2);

/* Use cert1 to verify cert2's embedded signature.
 */
int sigcert_verify_cert (const struct sigcert *cert1,
                         const struct sigcert *cert2);


/* Get/set metadata
 */
int sigcert_meta_sets (struct sigcert *cert,
                       const char *key, const char *value);
int sigcert_meta_gets (const struct sigcert *cert,
                       const char *key, const char **value);
int sigcert_meta_seti (struct sigcert *cert,
                       const char *key, int64_t value);
int sigcert_meta_geti (const struct sigcert *cert,
                       const char *key, int64_t *value);
int sigcert_meta_setd (struct sigcert *cert,
                       const char *key, double value);
int sigcert_meta_getd (const struct sigcert *cert,
                       const char *key, double *value);
int sigcert_meta_setb (struct sigcert *cert,
                       const char *key, bool value);
int sigcert_meta_getb (const struct sigcert *cert,
                       const char *key, bool *value);
int sigcert_meta_setts (struct sigcert *cert,
                        const char *key, time_t value);
int sigcert_meta_getts (const struct sigcert *cert,
                        const char *key, time_t *value);

#ifdef __cplusplus
}
#endif

#endif /* !_UTIL_SIGCERT_H */

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
