#if HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "src/libtap/tap.h"
#include "signer.h"
#include "ca.h"
#include "cf.h"

const char *ca_cf = \
"max-cert-ttl = 60\n" \
"max-sign-ttl = 30\n" \
"cert-path = \"/tmp/test-ca-cert\"\n" \
"revoke-dir = \"/tmp/test-ca-revoke\"\n" \
"revoke-allow = true\n" \
"domain = \"FLUX.TEST\"\n";

/* Generate CA certificate in memory.
 */
struct ca *create_ca (void)
{
    struct ca *ca;
    ca_error_t e;
    struct cf_error error;
    cf_t *cf;

    if (!(cf = cf_create ()))
        BAIL_OUT ("cf_create failed");
    if (cf_update (cf, ca_cf, strlen (ca_cf), &error) < 0)
        BAIL_OUT ("cf_update failed");

    if (!(ca = ca_create (cf, e)))
        BAIL_OUT ("ca_create failed: %s", e);
    if (ca_keygen (ca, 0, 0, e) < 0)
        BAIL_OUT ("ca_keygen failed: %s", e);
    cf_destroy (cf);

    return ca;
}

/* Destroy ca class, and unlink CA certifcate from configured location.
 */
void destroy_ca (struct ca *ca)
{
    ca_destroy (ca);
}

/* Create cert for userid and sign with CA.
 */
struct sigcert *create_cert (struct ca *ca, int64_t userid, int64_t ttl)
{
    struct sigcert *cert;
    ca_error_t e;

    if (!(cert = sigcert_create ()))
        BAIL_OUT ("sigcert_create failed");
    if (ca_sign (ca, cert, 0, ttl, userid, e) < 0)
        BAIL_OUT ("ca_sign: %s", e);
    return cert;
}

static void test_basic (void)
{
    struct ca *ca;
    struct signer *signer;
    signer_error_t e;
    struct sigcert *cert;
    const char *s;
    const char message[] = "test-message";
    const void *out;
    int len;
    int64_t uid, uid2;
    char *cpy, *bads;

    /* Create ca and signed user cert.
     */
    uid = getuid ();
    ca = create_ca ();
    cert = create_cert (ca, uid, 60);

    /* Wrap/unwrap test message and verify results.
     */
    signer = signer_create ();
    ok (signer != NULL,
        "signer_create works");

    s = signer_wrap (signer, cert, 30, message, strlen (message) + 1, e);
    ok (s != NULL,
        "signer_wrap works");
    diag ("out: %s", s);
    cpy = strdup (s);

    out = NULL;
    len = -1;
    uid2 = -1;
    ok (signer_unwrap (signer, ca, s, &out, &len, &uid2, e) == 0,
        "signer_unwrap works");
    ok (len == strlen (message) + 1,
        "unwrapped payload has correct size");
    ok (out != NULL && !strcmp (message, out),
        "unwrapped payload has correct content");
    ok (uid2 == uid,
        "unwrapped userid is same as original");

    /* Alter a byte in encoded header.
     * Header decode will fail with ENOENT (getting ctime).
     */
    if (!(bads = strdup (cpy)))
        BAIL_OUT ("strdup failed");
    bads[0] = 'a';
    errno = 0;
    *e = '\0';
    ok (signer_unwrap (signer, ca, bads, &out, &len, &uid2, e) < 0
        && errno == EINVAL && *e,
        "signer_unwrap (bad header) fails with EINVAL and sets e");
    diag ("%s", e);
    free (bads);

    /* Alter a byte in signature.
     * Sig verification will fail.
     */
    if (!(bads = strdup (cpy)))
        BAIL_OUT ("strdup failed");
    bads[strlen (bads) - 1] = 'a';
    errno = 0;
    *e = '\0';
    ok (signer_unwrap (signer, ca, bads, &out, &len, &uid2, e) < 0
        && errno == EINVAL && *e,
        "signer_unwrap (bad signature) fails with EINVAL and sets e");
    diag ("%s", e);
    free (bads);

    /* Alter a byte in payload.
     * Sig verification will fail.
     */
    if (!(bads = strdup (cpy)))
        BAIL_OUT ("strdup failed");
    char *p = strchr (bads, '.');
    *(p + 1) = 'a';
    errno = 0;
    *e = '\0';
    ok (signer_unwrap (signer, ca, bads, &out, &len, &uid2, e) < 0
        && errno == EINVAL && *e,
        "signer_unwrap (bad payload) fails with EINVAL and e is set");
    diag ("%s", e);
    free (bads);

    free (cpy);
    signer_destroy (signer);

    sigcert_destroy (cert);
    destroy_ca (ca);
}

void test_corner (void)
{
    struct ca *ca;
    struct signer *signer;
    signer_error_t e;
    struct sigcert *cert;
    const char message[] = "test-message";
    int64_t uid;
    const char *s;
    char *cpy;

    uid = getuid ();
    ca = create_ca ();
    cert = create_cert (ca, uid, 60);
    if (!(signer = signer_create ()))
        BAIL_OUT ("signer_create failed");

    errno = 0;
    *e = '\0';
    ok (signer_wrap (NULL, cert, 30, message, strlen (message) + 1, e) == NULL
        && errno == EINVAL && *e,
        "signer_wrap (signer=NULL) fails with EINVAL and sets e");

    errno = 0;
    *e = '\0';
    ok (signer_wrap (signer, NULL, 30, message, strlen (message) + 1, e) == NULL
        && errno == EINVAL && *e,
        "signer_wrap (cert=NULL) fails with EINVAL and sets e");

    errno = 0;
    *e = '\0';
    ok (signer_wrap (signer, cert, 30, message, -1, e) == NULL
        && errno == EINVAL && *e,
        "signer_wrap (payzs=-1) fails with EINVAL and sets e");

    errno = 0;
    *e = '\0';
    ok (signer_wrap (signer, cert, 30, NULL, 1, e) == NULL
        && errno == EINVAL && *e,
        "signer_wrap (pay=NUL,payzs=1) fails with EINVAL and sets e");

    errno = 0;
    *e = '\0';
    ok (signer_wrap (signer, cert, -1, message, strlen (message), e) == NULL
        && errno == EINVAL && *e,
        "signer_wrap (ttl=-1) fails with EINVAL and sets e");

    ok ((s = signer_wrap (signer, cert, 30, NULL, 0, e)) != NULL,
        "signer_wrap (pay=NULL,paysz=0) works");
    diag ("empty payload: %s", s);
    if (!(cpy = strdup (s)))
        BAIL_OUT ("strdup failed");

    errno = 0;
    *e = '\0';
    ok (signer_unwrap (NULL, ca, cpy, NULL, NULL, NULL, e) < 0
        && errno == EINVAL && *e,
        "signer_unwrap (signer=NULL) fails with EINVAL and sets e");

    errno = 0;
    *e = '\0';
    ok (signer_unwrap (signer, NULL, cpy, NULL, NULL, NULL, e) < 0
        && errno == EINVAL && *e,
        "signer_unwrap (ca=NULL) fails with EINVAL and sets e");

    errno = 0;
    *e = '\0';
    ok (signer_unwrap (signer, ca, NULL, NULL, NULL, NULL, e) < 0
        && errno == EINVAL && *e,
        "signer_unwrap (s=NULL) fails with EINVAL and sets e");

    free (cpy);
    signer_destroy (signer);
    sigcert_destroy (cert);
    destroy_ca (ca);
}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);

    test_basic ();
    test_corner ();

    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */
