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

static char scratch[PATH_MAX + 1];
static char keypath[PATH_MAX + 1];

/* Create a scratch directory in /tmp
 */
static void new_scratchdir (void)
{
    unsigned int n;
    const char *tmpdir = getenv ("TMPDIR");
    if (!tmpdir)
        tmpdir = "/tmp";
    n = snprintf (scratch, sizeof (scratch), "%s/sigcert.XXXXXX", tmpdir);
    if (n >= sizeof (scratch))
        BAIL_OUT ("scratch directory overflow");
    if (!mkdtemp (scratch))
        BAIL_OUT ("mkdtemp %s failed", scratch);
}

/* Remove scratch directory, assuming it is empty now.
 */
static void cleanup_scratchdir (void)
{
    if (rmdir (scratch) < 0)
        BAIL_OUT ("rmdir %s failed: %s", strerror (errno));
}

/* Construct a path relative to scratch directory.
 * Overwrites last result.
 */
static const char *new_keypath (const char *name)
{
    unsigned int n;

    if (strlen (scratch) == 0)
        BAIL_OUT ("keypath cannot be called before new_scratchdir");
    n = snprintf (keypath, sizeof (keypath), "%s/%s", scratch, name);
    if (n >= sizeof (keypath))
        BAIL_OUT ("keypath overflow");
    return keypath;
}

/* Construct and unlink a path relative to scratch directory.
 * Overwrites last result.
 */
static void cleanup_keypath (const char *name)
{
    const char *path = new_keypath (name);
    (void)unlink (path);
}

void test_load_store (void)
{
    struct flux_sigcert *cert;
    struct flux_sigcert *cert2;
    const char *name;

    new_scratchdir ();

    /* Create a certificate.
     * Create another one and make sure keys are different.
     */
    cert = flux_sigcert_create ();
    ok (cert != NULL,
        "flux_sigcert_create works");
    cert2 = flux_sigcert_create ();
    ok (cert2 != NULL && flux_sigcert_equal (cert, cert2) == false,
        "a second cert is different");
    flux_sigcert_destroy (cert2);

    /* Store the first certificate as TOML files (test, test.pub).
     * Load it back into a different cert, and make sure keys are the same.
     */
    name = new_keypath ("test");
    ok (flux_sigcert_store (cert, name) == 0,
        "flux_sigcert_store test, test.pub worked");
    ok ((cert2 = flux_sigcert_load (name)) != NULL,
        "flux_sigcert_load test worked");
    ok (flux_sigcert_equal (cert, cert2) == true,
        "loaded cert is same as the original");
    flux_sigcert_destroy (cert2);

    /* Verify file mode on certs.
     */
    struct stat sb;
    name = new_keypath ("test");
    ok (stat (name, &sb) == 0 && !(sb.st_mode & (S_IRGRP|S_IROTH))
                              && !(sb.st_mode & (S_IWGRP|S_IWOTH)),
        "secret cert file is not read/writeable by group,other");
    name = new_keypath ("test.pub");
    ok (stat (name, &sb) == 0 && !(sb.st_mode & (S_IWGRP|S_IWOTH)),
        "public cert file mode not writeable by group,other");

    /* Load just the public key and verify keys are different
     */
    name = new_keypath ("test.pub");
    ok ((cert2 = flux_sigcert_load (name)) != NULL,
        "flux_sigcert_load test.pub worked");
    ok (flux_sigcert_equal (cert, cert2) == false,
        "pub cert differs from secret one");
    flux_sigcert_destroy (cert2);

    /* Store new cert on top of existing one.
     */
    name = new_keypath ("test"); // exists
    cert2 = flux_sigcert_create ();
    if (!cert2)
        BAIL_OUT ("flux_sigcert_create: %s", strerror (errno));
    ok (flux_sigcert_store (cert2, name) == 0,
        "flux_sigcert_store overwrites existing cert");
    flux_sigcert_destroy (cert2);

    /* Store cert using relative path.
     */
    char cwd[PATH_MAX + 1];
    if (!getcwd (cwd, sizeof (cwd)))
        BAIL_OUT ("getcwd: %s", strerror (errno));
    if (chdir (scratch) < 0)
        BAIL_OUT ("chdir %s: %s", scratch, strerror (errno));
    ok (flux_sigcert_store (cert, "foo") == 0,
        "flux_sigcert_store works with relative path");
    cert2 = flux_sigcert_load ("foo");
    ok (cert2 != NULL,
        "flux_sigcert_load works with relative path");
    if (chdir (cwd) < 0)
        BAIL_OUT ("chdir %s: %s", cwd, strerror (errno));
    flux_sigcert_destroy (cert2);

    flux_sigcert_destroy (cert);

    cleanup_keypath ("test");
    cleanup_keypath ("test.pub");
    cleanup_keypath ("foo");
    cleanup_keypath ("foo.pub");
    cleanup_scratchdir ();
}

void test_sign_verify (void)
{
    struct flux_sigcert *cert1;
    struct flux_sigcert *cert2;
    uint8_t message[] = "foo-bar-baz";
    uint8_t tampered[] = "foo-KITTENS-baz";
    char *sig, *sig2;

    if (!(cert1 = flux_sigcert_create ()))
        BAIL_OUT ("flux_sigcert_create: %s", strerror (errno));
    if (!(cert2 = flux_sigcert_create ()))
        BAIL_OUT ("flux_sigcert_create: %s", strerror (errno));

    /* Sign message with cert1.
     * Verify message with cert1.
     * Demonstrate cert2 cannot verify message.
     * Demonstrate cert1 fails to verify if message changes.
     */
    sig = flux_sigcert_sign (cert1, message, sizeof (message));
    ok (sig != NULL,
        "flux_sigcert_sign works");
    diag ("%s", sig ? sig : "NULL");
    ok (flux_sigcert_verify (cert1, sig, message, sizeof (message)) == 0,
        "flux_sigcert_verify cert=good works");
    errno = 0;
    ok (flux_sigcert_verify (cert2, sig, message, sizeof (message)) < 0
        && errno == EINVAL,
        "flux_sigcert_verify cert=bad fails with EINVAL");
    errno = 0;
    ok (flux_sigcert_verify (cert1, sig, tampered, sizeof (tampered)) < 0
        && errno == EINVAL,
        "flux_sigcert_verify tampered fails with EINVAL");
    errno = 0;
    free (sig);

    /* Sign tampered message with cert2.
     * Verify that this signature cannot verify message.
     */
    sig2 = flux_sigcert_sign (cert1, tampered, sizeof (tampered));
    ok (sig2 != NULL,
        "flux_sigcert_sign works");
    errno = 0;
    ok (flux_sigcert_verify (cert1, sig2, message, sizeof (message)) < 0
        && errno == EINVAL,
        "flux_sigcert_verify sig=wrong fails with EINVAL");
    free (sig2);

    /* Sign/verify a zero-length message.
     */
    sig2 = flux_sigcert_sign (cert1, NULL, 0);
    ok (sig2 != NULL,
        "flux_sigcert_sign works on zero-length message");
    ok (flux_sigcert_verify (cert1, sig2, NULL, 0) == 0,
        "flux_sigcert_verify works on zero-length message");
    free (sig2);

    flux_sigcert_destroy (cert1);
    flux_sigcert_destroy (cert2);
}

void test_json_load_dump (void)
{
    struct flux_sigcert *cert;
    struct flux_sigcert *cert_pub;
    char *s, *sig;
    uint8_t message[] = "bad-kitty-my-pot-pie";

    if (!(cert = flux_sigcert_create ()))
        BAIL_OUT ("flux_sigcert_create: %s", strerror (errno));

    /* dump/load through JSON functions, creating a second cert with
     * public key only
     */
    s = flux_sigcert_json_dumps (cert);
    ok (s != NULL,
        "flux_sigcert_json_dumps works");
    cert_pub = flux_sigcert_json_loads (s);
    ok (cert_pub != NULL,
        "flux_sigcert_json_loads works");

    /* sign with cert, verify with public cert
     */
    if (!(sig = flux_sigcert_sign (cert, message, sizeof (message))))
        BAIL_OUT ("flux_sigcert_sign: %s", strerror (errno));
    ok (flux_sigcert_verify (cert_pub, sig, message, sizeof (message)) == 0,
        "verified sig with pub cert after json_dumps/loads");

    free (sig);
    free (s);
    flux_sigcert_destroy (cert);
    flux_sigcert_destroy (cert_pub);
}

void test_corner (void)
{
    struct flux_sigcert *cert;

    if (!(cert = flux_sigcert_create ()))
        BAIL_OUT ("flux_sigcert_create: %s", strerror (errno));

    /* Load/store corner cases
     */
    errno = 0;
    ok (flux_sigcert_store (cert, NULL) < 0 && errno == EINVAL,
        "flux_sigcert_store name=NULL fails with EINVAL");
    errno = 0;
    ok (flux_sigcert_store (cert, "") < 0 && errno == EINVAL,
        "flux_sigcert_store name=\"\" fails with EINVAL");
    errno = 0;
    ok (flux_sigcert_store (NULL, "foo") < 0 && errno == EINVAL,
        "flux_sigcert_store cert=NULL fails with EINVAL");
    errno = 0;
    ok (flux_sigcert_load (NULL) == NULL && errno == EINVAL,
        "flux_sigcert_load name=NULL fails with EINVAL");
    errno = 0;
    ok (flux_sigcert_load ("/noexist") == NULL && errno == ENOENT,
        "flux_sigcert_load name=/noexist fails with ENOENT");
    ok (flux_sigcert_equal (NULL, cert) == false,
        "flux_sigcert_load cert1=NULL returns false");
    ok (flux_sigcert_equal (cert, NULL) == false,
        "flux_sigcert_load cert2=NULL returns false");
    ok (flux_sigcert_equal (NULL, NULL) == false,
        "flux_sigcert_load both=NULL returns false");
    ok (flux_sigcert_equal (cert, cert) == true,
        "flux_sigcert_load both=same returns true");

    /* Sign/verify corner cases
     */
    uint8_t data[] = "foo";
    errno = 0;
    ok (flux_sigcert_sign (NULL, NULL, 0) == NULL && errno == EINVAL,
        "flux_sigcet_sign cert=NULL fails with EINVAL");
    errno = 0;
    ok (flux_sigcert_sign (cert, data, -1) == NULL && errno == EINVAL,
        "flux_sigcet_sign len<0 fails with EINVAL");
    errno = 0;
    ok (flux_sigcert_sign (cert, NULL, 1) == NULL && errno == EINVAL,
        "flux_sigcet_sign len>0 buf=NULL fails with EINVAL");
    errno = 0;
    ok (flux_sigcert_verify (NULL, "foo", NULL, 0) < 0 && errno == EINVAL,
        "flux_sigcert_verify cert=NULL fails with EINVAL");
    errno = 0;
    ok (flux_sigcert_verify (cert, NULL, NULL, 0) < 0 && errno == EINVAL,
        "flux_sigcert_verify sig=NULL fails with EINVAL");
    errno = 0;
    ok (flux_sigcert_verify (cert, "foo", NULL, -1) < 0 && errno == EINVAL,
        "flux_sigcert_verify len<0 fails with EINVAL");
    errno = 0;
    ok (flux_sigcert_verify (cert, "foo", NULL, 1) < 0 && errno == EINVAL,
        "flux_sigcert_verify len>0 buf=NULL fails with EINVAL");
    errno = 0;
    ok (flux_sigcert_verify (cert, "....", NULL, 0) < 0 && errno == EINVAL,
        "flux_sigcert_verify sig=invalid fails with EINVAL");

    /* json_dumps/loads corner cases
     */
    errno = 0;
    ok (flux_sigcert_json_dumps (NULL) == NULL && errno == EINVAL,
        "flux_sigcert_json_dumps cert=NULL fails with EINVAL");
    errno = 0;
    ok (flux_sigcert_json_loads (NULL) == NULL && errno == EINVAL,
        "flux_sigcert_json_loads s=NULL fails with EINVAL");
    errno = 0;
    ok (flux_sigcert_json_loads ("") == NULL && errno == EPROTO,
        "flux_sigcert_json_loads s=empty fails with EPROTO");
    errno = 0;
    ok (flux_sigcert_json_loads ("{") == NULL && errno == EPROTO,
        "flux_sigcert_json_loads s=invalid fails with EPROTO");
    errno = 0;
    ok (flux_sigcert_json_loads ("{\"curve\":{}}") == NULL && errno == EPROTO,
        "flux_sigcert_json_loads s=valid/wrong fails with EPROTO");

    /* Destroy NULL
     */
    lives_ok ({flux_sigcert_destroy (NULL);},
        "flux_sigcert_destroy cert=NULL doesn't crash");

    flux_sigcert_destroy (cert);
}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);

    test_load_store ();
    test_sign_verify();
    test_json_load_dump ();

    test_corner ();

    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */

