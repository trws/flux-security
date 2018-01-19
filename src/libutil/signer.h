#ifndef _UTIL_SIGNER_H
#define _UTIL_SIGNER_H

#include <stdint.h>

#include "sigcert.h"
#include "ca.h"

/* A payload (arbitrary byte sequence) is signed with a user's certificate
 * including secret key, producing a message consisting of three base64
 * substrings separated by periods: HEADER.PAYLOAD.SIGNATURE.
 *
 * The SIGNATURE covers the HEADER.PAYLOAD portion.
 * It is a base64-encoded ed25519 signature.
 *
 * The PAYLOAD is simply the base64-encoded payload.
 *
 * The HEADER is a base64-encoded "kv" object (see kv.h), including:
 * ctime - timestamp for signing
 * xtime - expiration time after which signature is no longer valid
 * cert - user cert including userid and public key, signed by CA
 *
 * A message is authenticated by decoding the HEADER, then using the
 * enclosed cert public key to validate SIGNATURE over HEADER.PAYLOAD,
 * then using the CA public key to validate the CA signature in the
 * enclosed cert.
 */

typedef char signer_error_t[200];

/* Create/destroy object for signing/verifying payloads.
 */
struct signer *signer_create (void);
void signer_destroy (struct signer *signer);

/* Sign payload 'pay' of 'paysz' bytes using 'cert'.
 * The result is a NULL-terminated string suitable as input to signer_unwrap().
 * The string is valid until the next call to signer_wrap/unwrap/destroy().
 * Returns string on success, or NULL on failure with errno set.
 * On failure, if error is non-NULL, it contain a textual error message.
 */
const char *signer_wrap (struct signer *signer,
                         const struct sigcert *cert, int64_t ttl,
                         const void *pay, int paysz, signer_error_t error);

/* Validate signature of NULL terminated string 'input'.
 * As part of validation, enclosed public certificate is validated with 'ca'.
 * If 'pay' and 'paysz' are non-NULL, set then to unwrapped payload, which
 * remains valid until the next call to signer_wrap/unwrap/destroy().
 * If 'userid' is non-NULL, it is set to the userid from the cert.
 * Returns 0 on success, or -1 on failure with errno set.
 * On failure, if error is non-NULL, it contain a textual error message.
 */
int signer_unwrap (struct signer *signer, const struct ca *ca,
                   const char *input,
                   const void **pay, int *paysz, int64_t *userid,
                   signer_error_t error);

#endif /* !_UTIL_SIGNER_H */

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
