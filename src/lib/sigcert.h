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
int flux_sigcert_store (struct flux_sigcert *cert, const char *name);

/* Decode JSON string to cert.
 */
struct flux_sigcert *flux_sigcert_json_loads (const char *s);

/* Encode public cert to JSON string.  Caller must free.
 */
char *flux_sigcert_json_dumps (struct flux_sigcert *cert);

/* Return true if two certificates have the same keys.
 */
bool flux_sigcert_equal (struct flux_sigcert *cert1,
                         struct flux_sigcert *cert2);

/* Return a detached signature (base64 string) over buf, len.
 * Caller must free.
 */
char *flux_sigcert_sign (struct flux_sigcert *cert,
                         uint8_t *buf, int len);

/* Verify a detached signature (base64 string) over buf, len.
 * Returns 0 on success, -1 on failure.
 */
int flux_sigcert_verify (struct flux_sigcert *cert,
                         const char *signature, uint8_t *buf, int len);


/* Get/set metadata
 */
int flux_sigcert_meta_set (struct flux_sigcert *cert, const char *key,
                           const char *value);
const char *flux_sigcert_meta_get (struct flux_sigcert *cert, const char *key);

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */

#ifdef __cplusplus
}
#endif

#endif /* !_FLUX_SIGCERT_H */

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
