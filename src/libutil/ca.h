#ifndef _UTIL_CA_H
#define _UTIL_CA_H

#include <time.h>

#include "sigcert.h"
#include "cf.h"

/* Mechanism:
 *
 * A CA cert is used to sign user certs.  The CA authenticates a user and
 * sets the userid and other metadata in the cert before signing it.
 * The CA signing process involves the CA secret key and may be localized
 * to a controlled environment to protect it. The user only provides the
 * public part of the user cert during CA signing.
 *
 * A user may sign data with their secret key, then enclose the signature,
 * the signed user cert containing the public key, and the data in a message.
 *
 * The message may be authenticated by validating the signature using the
 * enclosed cert, then validating the cert's signature using the CA public
 * key and comparing userids. The CA public key must be available in
 * environments that will authenticate messages.
 *
 * Cert revocation consists of placing the uuid of a cert in a directory
 * that is propagated along with the CA public key.
 */

typedef char ca_error_t[200];

/* Create/destroy ca object.
 * Returns 0 on success, -1 on failure with errno set.
 * On failure, if 'error' is non-NULL, it will contain a textual error message.
 */
struct ca *ca_create (const cf_t *ca_config, ca_error_t error);
void ca_destroy (struct ca *ca);

/* Add/update CA-required metadata to 'cert', then sign it.
 * This function fails if the CA secret key has not been loaded with ca_load
 * or ca_keygen.  'not_valid_before_time' can be a UTC wallclock time_t, or
 * 0=now. 'ttl' (seconds) must not exceed 'max-cert-ttl' (0 = maximum).
 * 'userid' should be authenticated to match the requesting user (the owner
 * of the certificate). Return 0 on success, -1 on failure with errno set.
 * On failure, if 'error' is non-NULL, it will contain a textual error message.
 */
int ca_sign (const struct ca *ca, struct sigcert *cert,
             time_t not_valid_before_time, int64_t ttl,
             int64_t userid, ca_error_t error);

/* Add cert identified by 'uuid' to the revocation list.
 * This creates an empty file named 'uuid' in 'revoke-dir'.
 * This function fails if 'revoke-allow' is false on this node,
 * or if the process does not have write permission to that directory.
 * Return 0 on success, -1 on failure with errno set.
 * On failure, if 'error' is non-NULL, it will contain a textual error message.
 */
int ca_revoke (const struct ca *ca, const char *uuid, ca_error_t error);

/* Verify that cert was signed by CA and has not expired or been revoked.
 * This function fails if the CA public key has not been loaded with ca_load
 * or ca_keygen.  Return the userid in 'userid' if non-NULL.
 * Return the max-sign-ttl in 'max_sign_ttl' if non-NULL.
 * Return 0 on success, -1 on failure with errno set.
 * On failure, if 'error' is non-NULL, it will contain a textual error message.
 */
int ca_verify (const struct ca *ca, const struct sigcert *cert,
               int64_t *userid, int64_t *max_sign_ttl, ca_error_t error);

/* Generate new CA cert in memory, replacing any cached cert with the new one.
 * Return 0 on success, -1 on failure with errno set.
 * On failure, if 'error' is non-NULL, it will contain a textual error message.
 */
int ca_keygen (struct ca *ca, time_t not_valid_before_time,
               int64_t ttl, ca_error_t error);

/* Store CA cert to configured path.
 * Return 0 on success, -1 on failure with errno set.
 * On failure, if 'error' is non-NULL, it will contain a textual error message.
 */
int ca_store (const struct ca *ca, ca_error_t error);

/* Load CA cert from configured path, replacing any cached cert with load one.
 * Call with secret=true to load secret key for signing certs.
 * Call with secret=false to load only public key for verifying certs.
 * Return 0 on success, -1 on failure with errno set.
 * On failure, if 'error' is non-NULL, it will contain a textual error message.
 */
int ca_load (struct ca *ca, bool secret, ca_error_t error);

/* Accessors for the CA cert.
 * (Mainly for test at this time).
 */
const struct sigcert *ca_get_cert (struct ca *ca, ca_error_t error);
int ca_set_cert (struct ca *ca, const struct sigcert *cert, ca_error_t error);

#endif // _UTIL_CA_H

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
