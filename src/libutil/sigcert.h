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

/* Copy cert.
 */
struct sigcert *sigcert_copy (struct sigcert *cert);

/* Drop secret key from cert.
 */
void sigcert_forget_secret (struct sigcert *cert);

/* Load cert from file 'name.pub'.
 * If secret=true, load secret-key from 'name' also.
 */
struct sigcert *sigcert_load (const char *name, bool secret);

/* Store cert to 'name' and 'name.pub'.
 */
int sigcert_store (const struct sigcert *cert, const char *name);

/* Decode kv buffer to cert.
 */
struct sigcert *sigcert_decode (const char *s, int len);

/* Encode cert to kv buffer.
 */
int sigcert_encode (const struct sigcert *cert, const char **bp, int *len);

/* Return true if two certificates have the same keys.
 */
bool sigcert_equal (const struct sigcert *cert1,
                    const struct sigcert *cert2);

/* Return a detached signature (base64 string) over buf, len.
 * Caller must free.
 */
char *sigcert_sign_detached (const struct sigcert *cert,
                             const uint8_t *buf, int len);

/* Verify a detached signature (base64 string) over buf, len.
 * Returns 0 on success, -1 on failure.
 */
int sigcert_verify_detached (const struct sigcert *cert,
                             const char *signature,
                             const uint8_t *buf, int len);

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
enum sigcert_meta_type {
    SM_UNKNOWN = 0,
    SM_STRING = 's',
    SM_INT64 = 'i',
    SM_DOUBLE = 'd',
    SM_BOOL = 'b',
    SM_TIMESTAMP = 't',
};

/* Set meta value.
 * N.B. take care that SM_INT64 and SM_TIMESTAMP arguments are the expected
 * size, remembering that default integer argument promotion is to "int".
 * Returns 0 on success, -1 on failure with errno set.
 */
int sigcert_meta_set (struct sigcert *cert, const char *key,
                      enum sigcert_meta_type type, ...);

/* Get meta value.
 * Returns 0 on success, -1 on failure with errno set.
 */
int sigcert_meta_get (const struct sigcert *cert, const char *key,
                      enum sigcert_meta_type type, ...);

#ifdef __cplusplus
}
#endif

#endif /* !_UTIL_SIGCERT_H */

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
