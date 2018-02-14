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
#include "sigcert.h"
#include "ca.h"
#include "cf.h"

const char *conf_tmpl = \
"max-cert-ttl = 60\n" \
"max-sign-ttl = 30\n" \
"cert-path = \"%s/ca-cert\"\n" \
"revoke-dir = \"%s/ca-revoke\"\n" \
"revoke-allow = true\n" \
"domain = \"FLUX.TEST\"\n";

static cf_t *cf;
static char tmpdir[PATH_MAX + 1];

/* Initialize configuration with paths pointing to a tmp directory
 * Return [ca] config table.
 */
void cf_init (void)
{
    struct cf_error error;
    char conf[256];
    const char *t = getenv ("TMPDIR");

    if (snprintf (tmpdir, sizeof (tmpdir), "%s/ca-XXXXXX",
                  t ? t : "/tmp") >= sizeof (tmpdir))
        BAIL_OUT ("tmpdir buffer overflow");
    if (!mkdtemp (tmpdir))
        BAIL_OUT ("mkdtemp: %s", strerror (errno));
    if (snprintf (conf, sizeof (conf), conf_tmpl,
                  tmpdir, tmpdir) >= sizeof (conf))
        BAIL_OUT ("conf buffer overflow)");
    if (!(cf = cf_create ()))
        BAIL_OUT ("cf_create: %s", strerror (errno));
    if (cf_update (cf, conf, strlen (conf), &error) < 0)
        BAIL_OUT ("cf_update: %s", errno == EINVAL ? error.errbuf
                                                   : strerror (errno));
}

void cf_fini (void)
{
    char path[PATH_MAX + 1];

    (void)snprintf (path, sizeof (path), "%s/ca-cert", tmpdir);
    (void)unlink (path);
    (void)snprintf (path, sizeof (path), "%s/ca-cert.pub", tmpdir);
    (void)unlink (path);
    if (rmdir (tmpdir) < 0)
        BAIL_OUT ("rmdir %s: %s", tmpdir, strerror (errno));

    cf_destroy (cf);
}

void test_basic (void)
{
    struct ca *ca;
    ca_error_t e;
    struct sigcert *cert;
    struct sigcert *badcert;
    int64_t userid;
    int64_t ttl;
    const char *uuid;
    char path[PATH_MAX + 1];

    /* Create ca with cert in memory.
     */
    ca = ca_create (cf, e);
    ok (ca != NULL,
        "ca_create works");
    if (!ca)
        BAIL_OUT ("ca_create: %s", e);
    errno = 0;
    ok (ca_load (ca, true, e) < 0 && errno == ENOENT && *e,
        "ca_load fails with ENOENT on nonexistent cert and sets e");
    ok (ca_keygen (ca, e) == 0,
        "ca_keygen works");

    /* Create user cert
     */
    if (!(cert = sigcert_create ()))
        BAIL_OUT ("sigcert_create failed");

    /* Verification fails before ca sign
     */
    errno = 0;
    ok (ca_verify (ca, cert, NULL, NULL, e) < 0 && errno == EINVAL,
        "ca_verify fails with EINVAL");
    diag ("%s", e);

    /* Sign cert with ca
     */
    ok (ca_sign (ca, cert, 0, getuid (), e) == 0,
        "ca_sign signed cert");

    /* Verify cert with ca
     */
    userid = 0;
    ttl = 0;
    ok (ca_verify (ca, cert, &userid, &ttl, e) == 0,
        "ca_verify works");
    ok (userid == getuid (),
        "userid is correct");
    ok (ttl == 30,
        "max-sign-ttl is correct");

    /* Save/restore CA cert to file system
     */
    ok (ca_store (ca, e) == 0,
        "ca_store works");
    ok (ca_load (ca, false, e) == 0,
        "ca_load secret=false works");
    ok (ca_verify (ca, cert, NULL, NULL, e) == 0,
        "ca_verify still works");
    errno = 0;
    ok (ca_sign (ca, cert, 0, getuid (), e) < 0 && errno == EINVAL,
        "ca_sign fails without secret key");
    diag ("%s", e);
    ok (ca_load (ca, true, e) == 0,
        "ca_load secret=true works");
    ok (ca_verify (ca, cert, NULL, NULL, e) == 0,
        "ca_verify still works");

    /* Change userid in cert
     */
    if (!(badcert = sigcert_copy (cert)))
        BAIL_OUT ("sigcert_copy: %s", strerror (errno));
    ok (sigcert_meta_set (badcert, "userid", SM_INT64, userid + 1) == 0,
        "changed userid in cert");
    errno = 0;
    ok (ca_verify (ca, badcert, NULL, NULL, e) < 0 && errno == EINVAL,
        "ca_verify fails with EINVAL");
    diag ("%s", e);
    sigcert_destroy (badcert);

    /* Revoke cert
     */
    if (sigcert_meta_get (cert, "uuid", SM_STRING, &uuid) < 0)
        BAIL_OUT ("failed to read cert uuid: %s", strerror (errno));
    ok (ca_revoke (ca, uuid, e) == 0,
        "sigcert revoke works");
    errno = 0;
    ok (ca_verify (ca, badcert, NULL, NULL, e) < 0 && errno == EINVAL,
        "ca_verify fails with EINVAL");
    diag ("%s", e);

    /* clean up revocation dir */
    snprintf (path, sizeof (path), "%s/ca-revoke/%s", tmpdir, uuid);
    if (unlink (path) < 0)
        BAIL_OUT ("%s: %s", path, strerror (errno));
    snprintf (path, sizeof (path), "%s/ca-revoke", tmpdir);
    if (rmdir (path) < 0)
        BAIL_OUT ("%s: %s", path, strerror (errno));

    sigcert_destroy (cert);
    ca_destroy (ca);
}

void test_corner (void)
{
    ca_error_t e;
    struct ca *ca;
    struct ca *canokey;
    cf_t *badcf;
    struct sigcert *cert;

    if (!(ca = ca_create (cf, NULL)))
        BAIL_OUT ("ca_create failed");
    if (ca_keygen (ca, e) < 0)
        BAIL_OUT ("ca_keygen failed");
    if (!(badcf = cf_create ()))
        BAIL_OUT ("cf_create failed");
    if (cf_update (badcf, "foo=42\n", 7, NULL) < 0)
        BAIL_OUT ("cf_update failed");
    if (!(cert = sigcert_create ()))
        BAIL_OUT ("sigcert_create failed");
    if (ca_sign (ca, cert, 30, getuid (), e) < 0)
        BAIL_OUT ("ca_sign failed");
    if (!(canokey = ca_create (cf, NULL)))
        BAIL_OUT ("ca_create nokey failed");

    errno = 0;
    *e = '\0';
    ok (!ca_create (NULL, e) && errno == EINVAL && *e,
        "ca_create cf=NULL fails with EINVAL and updates e");
    errno = 0;
    *e = '\0';
    ok (!ca_create (badcf, e) && errno == EINVAL && *e,
        "ca_create cf=(wrong) fails with EINVAL and updates e");

    lives_ok ({ca_destroy (NULL);},
        "ca_destroy ca=NULL doesn't crash");

    errno = 0;
    *e = '\0';
    ok (ca_sign (NULL, cert, 2, getuid (), e) < 0 && errno == EINVAL && *e,
        "ca_sign ca=NULL fails with EINVAL and updates e");
    errno = 0;
    *e = '\0';
    ok (ca_sign (ca, NULL, 2, getuid (), e) < 0 && errno == EINVAL && *e,
        "ca_sign cert=NULL fails with EINVAL and updates e");
    errno = 0;
    *e = '\0';
    ok (ca_sign (ca, cert, -1, getuid (), e) < 0 && errno == EINVAL && *e,
        "ca_sign ttl=-1 fails with EINVAL and updates e");
    errno = 0;
    *e = '\0';
    ok (ca_sign (ca, cert, 2, -1, e) < 0 && errno == EINVAL && *e,
        "ca_sign userid=-1 fails with EINVAL and updates e");
    errno = 0;
    *e = '\0';
    ok (ca_sign (canokey, cert, 2, getuid (), e) < 0 && errno == EINVAL && *e,
        "ca_sign ca=(nokeys) fails with EINVAL and updates e");

    ok (ca_verify (ca, cert, NULL, NULL, NULL) == 0,
        "test cert sig is still valid");

    errno = 0;
    *e = '\0';
    ok (ca_verify (NULL, cert, NULL, NULL, e) < 0 && errno == EINVAL && *e,
        "ca_verify ca=NULL fails with EINVAL and updates e");
    errno = 0;
    *e = '\0';
    ok (ca_verify (ca, NULL, NULL, NULL, e) < 0 && errno == EINVAL && *e,
        "ca_verify cert=NULL fails with EINVAL and updates e");
    errno = 0;
    *e = '\0';
    ok (ca_verify (canokey, cert, NULL, NULL, e) < 0 && errno == EINVAL && *e,
        "ca_verify cert=(nokeys) fails with EINVAL and updates e");

    errno = 0;
    *e = '\0';
    ok (ca_keygen (NULL, e) < 0 && errno == EINVAL && *e,
        "ca_keygen ca=NULL fails with EINVAL and updates e");

    errno = 0;
    *e = '\0';
    ok (ca_store (NULL, e) < 0 && errno == EINVAL && *e,
        "ca_store ca=NULL fails with EINVAL and updates e");
    errno = 0;
    *e = '\0';
    ok (ca_store (canokey, e) < 0 && errno == EINVAL && *e,
        "ca_store ca=(no keys) fails with EINVAL and updates e");
    errno = 0;
    *e = '\0';
    ok (ca_load (NULL, false, e) < 0 && errno == EINVAL && *e,
        "ca_load ca=NULL fails with EINVAL and updates e");

    errno = 0;
    *e = '\0';
    ok (ca_revoke (NULL, "xyz", e) < 0 && errno == EINVAL && *e,
        "ca_revoke ca=NULL fails with EINVAL and updates e");
    errno = 0;
    *e = '\0';
    ok (ca_revoke (ca, NULL, e) < 0 && errno == EINVAL && *e,
        "ca_revoke uuid=NULL fails with EINVAL and updates e");
    errno = 0;
    *e = '\0';
    ok (ca_revoke (ca, "", e) < 0 && errno == EINVAL && *e,
        "ca_revoke uuid=(empty) fails with EINVAL and updates e");

    sigcert_destroy (cert);
    cf_destroy (badcf);
    ca_destroy (ca);
    ca_destroy (canokey);
}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);

    cf_init ();

    test_basic ();
    test_corner ();

    cf_fini ();

    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */
