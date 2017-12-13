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

static void diag_cert (const char *prefix, struct sigcert *cert)
{
    char *s = sigcert_json_dumps (cert);
    diag ("%s: %s", prefix, s ? s : strerror (errno));
    free (s);
}

void test_meta (void)
{
    struct sigcert *cert;
    const char *s;
    int64_t i;
    double d;
    bool b;
    time_t t;
    time_t tnow = time (NULL);

    cert = sigcert_create ();
    ok (cert != NULL,
        "sigcert_create works");
    ok (sigcert_meta_sets (cert, "foo", "bar") == 0,
        "sigcert_meta_sets foo=bar");
    ok (sigcert_meta_seti (cert, "baz", 42) == 0,
        "sigcert_meta_seti baz=42");
    ok (sigcert_meta_setd (cert, "bar", 3.14159) == 0,
        "sigcert_meta_setd bar=3.14159");
    ok (sigcert_meta_setb (cert, "baf", true) == 0,
        "sigcert_meta_setd baf=true");
    ok (sigcert_meta_setts (cert, "ts", tnow) == 0,
        "sigcert_meta_setd ts=true");
    ok (sigcert_meta_gets (cert, "foo", &s) == 0
        && !strcmp (s, "bar"),
        "sigcert_meta_gets foo works");
    ok (sigcert_meta_geti (cert, "baz", &i) == 0
        && i == 42,
        "sigcert_meta_geti baz works");
    ok (sigcert_meta_getd (cert, "bar", &d) == 0 && d == 3.14159,
        "sigcert_meta_getd bar works");
    ok (sigcert_meta_getb (cert, "baf", &b) == 0 && b == true,
        "sigcert_meta_getb baf works");
    ok (sigcert_meta_getts (cert, "ts", &t) == 0 && t == tnow,
        "sigcert_meta_getts ts works");

    sigcert_destroy (cert);
}

void test_load_store (void)
{
    struct sigcert *cert;
    struct sigcert *cert2;
    const char *name;

    /* Create a certificate.
     * Create another one and make sure keys are different.
     */
    cert = sigcert_create ();
    ok (cert != NULL,
        "sigcert_create works");
    cert2 = sigcert_create ();
    ok (cert2 != NULL && sigcert_equal (cert, cert2) == false,
        "a second cert is different");
    sigcert_destroy (cert2);

    /* Store the first certificate as TOML files (test, test.pub).
     * Load it back into a different cert, and make sure keys are the same.
     */
    name = new_keypath ("test");
    ok (sigcert_meta_sets (cert, "foo", "bar") == 0,
        "sigcert_meta_sets foo=bar");
    ok (sigcert_meta_seti (cert, "bar", -55) == 0,
        "sigcert_meta_seti bar=-55");
    ok (sigcert_meta_setd (cert, "baz", 2.718) == 0,
        "sigcert_meta_setd baz=2.718");
    ok (sigcert_meta_setb (cert, "flag", false) == 0,
        "sigcert_meta_setb flag=false");
    ok (sigcert_meta_setts (cert, "time", time (NULL)) == 0,
        "sigcert_meta_setts time=now");
    ok (sigcert_store (cert, name) == 0,
        "sigcert_store test, test.pub worked");
    ok ((cert2 = sigcert_load (name, true)) != NULL,
        "sigcert_load test worked");
    diag_cert ("cert", cert);
    diag_cert ("cert2", cert2);
    ok (sigcert_equal (cert, cert2) == true,
        "loaded cert is same as the original");
    sigcert_destroy (cert2);

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
    name = new_keypath ("test");
    ok ((cert2 = sigcert_load (name, false)) != NULL,
        "sigcert_load test.pub worked");
    ok (sigcert_equal (cert, cert2) == false,
        "pub cert differs from secret one");
    sigcert_destroy (cert2);

    /* Store new cert on top of existing one.
     */
    name = new_keypath ("test"); // exists
    cert2 = sigcert_create ();
    if (!cert2)
        BAIL_OUT ("sigcert_create: %s", strerror (errno));
    ok (sigcert_store (cert2, name) == 0,
        "sigcert_store overwrites existing cert");
    sigcert_destroy (cert2);

    /* Store cert using relative path.
     */
    char cwd[PATH_MAX + 1];
    if (!getcwd (cwd, sizeof (cwd)))
        BAIL_OUT ("getcwd: %s", strerror (errno));
    if (chdir (scratch) < 0)
        BAIL_OUT ("chdir %s: %s", scratch, strerror (errno));
    ok (sigcert_store (cert, "foo") == 0,
        "sigcert_store works with relative path");
    cert2 = sigcert_load ("foo", true);
    ok (cert2 != NULL,
        "sigcert_load works with relative path");
    if (chdir (cwd) < 0)
        BAIL_OUT ("chdir %s: %s", cwd, strerror (errno));
    sigcert_destroy (cert2);

    sigcert_destroy (cert);

    cleanup_keypath ("test");
    cleanup_keypath ("test.pub");
    cleanup_keypath ("foo");
    cleanup_keypath ("foo.pub");
}

void test_sign_verify (void)
{
    struct sigcert *cert1;
    struct sigcert *cert2;
    uint8_t message[] = "foo-bar-baz";
    uint8_t tampered[] = "foo-KITTENS-baz";
    char *sig, *sig2;

    if (!(cert1 = sigcert_create ()))
        BAIL_OUT ("sigcert_create: %s", strerror (errno));
    if (!(cert2 = sigcert_create ()))
        BAIL_OUT ("sigcert_create: %s", strerror (errno));

    /* Sign message with cert1.
     * Verify message with cert1.
     * Demonstrate cert2 cannot verify message.
     * Demonstrate cert1 fails to verify if message changes.
     */
    sig = sigcert_sign (cert1, message, sizeof (message));
    ok (sig != NULL,
        "sigcert_sign works");
    diag ("%s", sig ? sig : "NULL");
    ok (sigcert_verify (cert1, sig, message, sizeof (message)) == 0,
        "sigcert_verify cert=good works");
    errno = 0;
    ok (sigcert_verify (cert2, sig, message, sizeof (message)) < 0
        && errno == EINVAL,
        "sigcert_verify cert=bad fails with EINVAL");
    errno = 0;
    ok (sigcert_verify (cert1, sig, tampered, sizeof (tampered)) < 0
        && errno == EINVAL,
        "sigcert_verify tampered fails with EINVAL");
    errno = 0;
    free (sig);

    /* Sign tampered message with cert2.
     * Verify that this signature cannot verify message.
     */
    sig2 = sigcert_sign (cert1, tampered, sizeof (tampered));
    ok (sig2 != NULL,
        "sigcert_sign works");
    errno = 0;
    ok (sigcert_verify (cert1, sig2, message, sizeof (message)) < 0
        && errno == EINVAL,
        "sigcert_verify sig=wrong fails with EINVAL");
    free (sig2);

    /* Sign/verify a zero-length message.
     */
    sig2 = sigcert_sign (cert1, NULL, 0);
    ok (sig2 != NULL,
        "sigcert_sign works on zero-length message");
    ok (sigcert_verify (cert1, sig2, NULL, 0) == 0,
        "sigcert_verify works on zero-length message");
    free (sig2);

    sigcert_destroy (cert1);
    sigcert_destroy (cert2);
}

void test_json_load_dump_sign (void)
{
    struct sigcert *cert;
    struct sigcert *cert_pub;
    char *s, *sig;
    uint8_t message[] = "bad-kitty-my-pot-pie";

    if (!(cert = sigcert_create ()))
        BAIL_OUT ("sigcert_create: %s", strerror (errno));

    /* dump/load through JSON functions, creating a second cert with
     * public key only
     */
    s = sigcert_json_dumps (cert);
    ok (s != NULL,
        "sigcert_json_dumps works");
    cert_pub = sigcert_json_loads (s);
    ok (cert_pub != NULL,
        "sigcert_json_loads works");

    /* sign with cert, verify with public cert
     */
    if (!(sig = sigcert_sign (cert, message, sizeof (message))))
        BAIL_OUT ("sigcert_sign: %s", strerror (errno));
    ok (sigcert_verify (cert_pub, sig, message, sizeof (message)) == 0,
        "verified sig with pub cert after json_dumps/loads");

    free (sig);
    free (s);
    sigcert_destroy (cert);
    sigcert_destroy (cert_pub);
}

void test_json_load_dump (void)
{
    struct sigcert *cert;
    struct sigcert *cert_pub;
    struct sigcert *cert2;
    char *s;
    const char *name;

    /* Store a cert to test, test.pub, then load cert_pub with
     * only the public key.
     */
    name = new_keypath ("test");
    if (!(cert = sigcert_create ()))
        BAIL_OUT ("sigcert_create");
    ok (sigcert_meta_sets (cert, "foo", "bar") == 0,
        "sigcert_meta_sets foo=bar");
    ok (sigcert_meta_seti (cert, "bar", 42) == 0,
        "sigcert_meta_seti bar=42");
    ok (sigcert_meta_setd (cert, "baz", 42e-27) == 0,
        "sigcert_meta_setd bar=42");
    ok (sigcert_meta_setb (cert, "nerf", true) == 0,
        "sigcert_meta_setb nerf=true");
    ok (sigcert_meta_setts (cert, "time", time (NULL)) == 0,
        "sigcert_meta_setb time=now");
    if (sigcert_store (cert, name) < 0)
        BAIL_OUT ("sigcert_store");
    ok ((cert_pub = sigcert_load (name, false)) != NULL,
        "sigcert_load test.pub worked");

    /* Dump cert_pub to json string, then load cert2 from
     * json_string, and test cert_pub and cert2 for equality.
     * Everything was properly marshaled.
     */
    s = sigcert_json_dumps (cert_pub);
    ok (s != NULL,
        "sigcert_json_dumps works");
    cert2 = sigcert_json_loads (s);
    ok (cert2 != NULL,
        "sigcert_json_loads works");
    ok (sigcert_equal (cert2, cert_pub) == true,
        "the two certs are equal");
    diag ("%s", s);

    free (s);
    sigcert_destroy (cert);
    sigcert_destroy (cert_pub);
    sigcert_destroy (cert2);

    cleanup_keypath ("test");
    cleanup_keypath ("test.pub");
}

void test_corner (void)
{
    struct sigcert *cert;

    if (!(cert = sigcert_create ()))
        BAIL_OUT ("sigcert_create: %s", strerror (errno));
    if (sigcert_meta_sets (cert, "test-s", "foo") < 0)
        BAIL_OUT ("meta_sets failed");
    if (sigcert_meta_seti (cert, "test-i", 42) < 0)
        BAIL_OUT ("meta_seti failed");
    if (sigcert_meta_setd (cert, "test-d", 3.14) < 0)
        BAIL_OUT ("meta_setd failed");
    if (sigcert_meta_setb (cert, "test-b", true) < 0)
        BAIL_OUT ("meta_setb failed");
    if (sigcert_meta_setts (cert, "test-ts", time (NULL)) < 0)
        BAIL_OUT ("meta_setts failed");

    /* Load/store corner cases
     */
    errno = 0;
    ok (sigcert_store (cert, NULL) < 0 && errno == EINVAL,
        "sigcert_store name=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_store (cert, "") < 0 && errno == EINVAL,
        "sigcert_store name=\"\" fails with EINVAL");
    errno = 0;
    ok (sigcert_store (NULL, "foo") < 0 && errno == EINVAL,
        "sigcert_store cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_load (NULL, true) == NULL && errno == EINVAL,
        "sigcert_load name=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_load ("/noexist", true) == NULL && errno == ENOENT,
        "sigcert_load name=/noexist fails with ENOENT");
    ok (sigcert_equal (NULL, cert) == false,
        "sigcert_load cert1=NULL returns false");
    ok (sigcert_equal (cert, NULL) == false,
        "sigcert_load cert2=NULL returns false");
    ok (sigcert_equal (NULL, NULL) == false,
        "sigcert_load both=NULL returns false");
    ok (sigcert_equal (cert, cert) == true,
        "sigcert_load both=same returns true");

    /* Sign/verify corner cases
     */
    uint8_t data[] = "foo";
    errno = 0;
    ok (sigcert_sign (NULL, NULL, 0) == NULL && errno == EINVAL,
        "flux_sigcet_sign cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_sign (cert, data, -1) == NULL && errno == EINVAL,
        "flux_sigcet_sign len<0 fails with EINVAL");
    errno = 0;
    ok (sigcert_sign (cert, NULL, 1) == NULL && errno == EINVAL,
        "flux_sigcet_sign len>0 buf=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_verify (NULL, "foo", NULL, 0) < 0 && errno == EINVAL,
        "sigcert_verify cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_verify (cert, NULL, NULL, 0) < 0 && errno == EINVAL,
        "sigcert_verify sig=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_verify (cert, "foo", NULL, -1) < 0 && errno == EINVAL,
        "sigcert_verify len<0 fails with EINVAL");
    errno = 0;
    ok (sigcert_verify (cert, "foo", NULL, 1) < 0 && errno == EINVAL,
        "sigcert_verify len>0 buf=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_verify (cert, "....", NULL, 0) < 0 && errno == EINVAL,
        "sigcert_verify sig=invalid fails with EINVAL");

    /* json_dumps/loads corner cases
     */
    errno = 0;
    ok (sigcert_json_dumps (NULL) == NULL && errno == EINVAL,
        "sigcert_json_dumps cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_json_loads (NULL) == NULL && errno == EINVAL,
        "sigcert_json_loads s=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_json_loads ("") == NULL && errno == EPROTO,
        "sigcert_json_loads s=empty fails with EPROTO");
    errno = 0;
    ok (sigcert_json_loads ("{") == NULL && errno == EPROTO,
        "sigcert_json_loads s=invalid fails with EPROTO");
    errno = 0;
    ok (sigcert_json_loads ("{\"curve\":{}}") == NULL && errno == EPROTO,
        "sigcert_json_loads s=valid/wrong fails with EPROTO");

    /* meta gets/sets corner cases
     */
    const char *s;
    errno = 0;
    ok (sigcert_meta_sets (NULL, "a", "b") < 0 && errno == EINVAL,
        "sigcert_meta_sets cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_sets (cert, NULL, "b") < 0 && errno == EINVAL,
        "sigcert_meta_sets key=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_sets (cert, "a.b", "b") < 0 && errno == EINVAL,
        "sigcert_meta_sets key=a.b fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_sets (cert, "a", NULL) < 0 && errno == EINVAL,
        "sigcert_meta_sets value=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_gets (NULL, "a", &s) < 0 && errno == EINVAL,
        "sigcert_meta_gets cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_gets (cert, NULL, &s) < 0 && errno == EINVAL,
        "sigcert_meta_gets key=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_gets (cert, ".", &s) < 0 && errno == EINVAL,
        "sigcert_meta_gets key=. fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_gets (cert, "a", NULL) < 0 && errno == EINVAL,
        "sigcert_meta_gets value=NULL fails with EINVAL");
    /* wrong type */
    errno = 0;
    ok (sigcert_meta_gets (cert, "test-i", &s) < 0 && errno == EINVAL,
        "sigcert_meta_gets on int fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_gets (cert, "test-d", &s) < 0 && errno == EINVAL,
        "sigcert_meta_gets on double fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_gets (cert, "test-b", &s) < 0 && errno == EINVAL,
        "sigcert_meta_gets on boolean fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_gets (cert, "test-ts", &s) < 0 && errno == EINVAL,
        "sigcert_meta_gets on timestamp fails with EINVAL");

    /* meta geti/seti corner cases
     */
    int64_t i;
    errno = 0;
    ok (sigcert_meta_seti (NULL, "a", 42) < 0 && errno == EINVAL,
        "sigcert_meta_seti cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_seti (cert, NULL, 42) < 0 && errno == EINVAL,
        "sigcert_meta_seti key=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_seti (cert, "a.b", 42) < 0 && errno == EINVAL,
        "sigcert_meta_seti key=a.b fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_geti (NULL, "a", &i) < 0 && errno == EINVAL,
        "sigcert_meta_geti cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_geti (cert, NULL, &i) < 0 && errno == EINVAL,
        "sigcert_meta_geti key=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_geti (cert, ".", &i) < 0 && errno == EINVAL,
        "sigcert_meta_geti key=. fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_geti (cert, "a", NULL) < 0 && errno == EINVAL,
        "sigcert_meta_geti value=NULL fails with EINVAL");
    /* wrong type */
    errno = 0;
    ok (sigcert_meta_geti (cert, "test-s", &i) < 0 && errno == EINVAL,
        "sigcert_meta_geti on string fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_geti (cert, "test-d", &i) < 0 && errno == EINVAL,
        "sigcert_meta_geti on double fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_geti (cert, "test-b", &i) < 0 && errno == EINVAL,
        "sigcert_meta_geti on boolean fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_geti (cert, "test-ts", &i) < 0 && errno == EINVAL,
        "sigcert_meta_geti on timestamp fails with EINVAL");

    /* meta getd/setd corner cases
     */
    double d;
    errno = 0;
    ok (sigcert_meta_setd (NULL, "a", 3.14) < 0 && errno == EINVAL,
        "sigcert_meta_setd cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_setd (cert, NULL, 3.14) < 0 && errno == EINVAL,
        "sigcert_meta_setd key=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_setd (cert, "a.b", 3.14) < 0 && errno == EINVAL,
        "sigcert_meta_setd key=a.b fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getd (NULL, "a", &d) < 0 && errno == EINVAL,
        "sigcert_meta_getd cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getd (cert, NULL, &d) < 0 && errno == EINVAL,
        "sigcert_meta_getd key=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getd (cert, ".", &d) < 0 && errno == EINVAL,
        "sigcert_meta_getd key=. fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getd (cert, "a", NULL) < 0 && errno == EINVAL,
        "sigcert_meta_getd value=NULL fails with EINVAL");
    /* wrong type */
    errno = 0;
    ok (sigcert_meta_getd (cert, "test-s", &d) < 0 && errno == EINVAL,
        "sigcert_meta_getd on string fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getd (cert, "test-i", &d) < 0 && errno == EINVAL,
        "sigcert_meta_getd on int fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getd (cert, "test-b", &d) < 0 && errno == EINVAL,
        "sigcert_meta_getd on boolean fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getd (cert, "test-ts", &d) < 0 && errno == EINVAL,
        "sigcert_meta_getd on timestamp fails with EINVAL");

    /* meta getb/setb corner cases
     */
    bool b;
    errno = 0;
    ok (sigcert_meta_setb (NULL, "a", false) < 0 && errno == EINVAL,
        "sigcert_meta_setb cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_setb (cert, NULL, false) < 0 && errno == EINVAL,
        "sigcert_meta_setb key=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_setb (cert, "a.b", false) < 0 && errno == EINVAL,
        "sigcert_meta_setb key=a.b fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getb (NULL, "a", &b) < 0 && errno == EINVAL,
        "sigcert_meta_getb cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getb (cert, NULL, &b) < 0 && errno == EINVAL,
        "sigcert_meta_getb key=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getb (cert, ".", &b) < 0 && errno == EINVAL,
        "sigcert_meta_getb key=. fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getb (cert, "a", NULL) < 0 && errno == EINVAL,
        "sigcert_meta_getb value=NULL fails with EINVAL");
    /* wrong type */
    errno = 0;
    ok (sigcert_meta_getb (cert, "test-s", &b) < 0 && errno == EINVAL,
        "sigcert_meta_getb on string fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getb (cert, "test-i", &b) < 0 && errno == EINVAL,
        "sigcert_meta_getb on int fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getb (cert, "test-d", &b) < 0 && errno == EINVAL,
        "sigcert_meta_getb on double fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getb (cert, "test-ts", &b) < 0 && errno == EINVAL,
        "sigcert_meta_getb on timestamp fails with EINVAL");

    /* meta getts/setts corner cases
     */
    time_t t;
    time_t tnow = time (NULL);
    const long yrsec = 60*60*24*365;
    time_t tbyo = tnow + yrsec*1E9;  // a billion years from now?
    errno = 0;
    ok (sigcert_meta_setts (NULL, "a", tnow) < 0 && errno == EINVAL,
        "sigcert_meta_setts cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_setts (cert, NULL, tnow) < 0 && errno == EINVAL,
        "sigcert_meta_setts key=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_setts (cert, "a.b", tnow) < 0 && errno == EINVAL,
        "sigcert_meta_setts key=a.b fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_setts (cert, "a.b", tbyo) < 0 && errno == EINVAL,
        "sigcert_meta_setts value=byo fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getts (NULL, "a", &t) < 0 && errno == EINVAL,
        "sigcert_meta_getts cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getts (cert, NULL, &t) < 0 && errno == EINVAL,
        "sigcert_meta_getts key=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getts (cert, ".", &t) < 0 && errno == EINVAL,
        "sigcert_meta_getts key=. fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getts (cert, "a", NULL) < 0 && errno == EINVAL,
        "sigcert_meta_getts value=NULL fails with EINVAL");
    /* wrong type */
    errno = 0;
    ok (sigcert_meta_getts (cert, "test-s", &t) < 0 && errno == EINVAL,
        "sigcert_meta_getts on string fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getts (cert, "test-i", &t) < 0 && errno == EINVAL,
        "sigcert_meta_getts on int fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getts (cert, "test-d", &t) < 0 && errno == EINVAL,
        "sigcert_meta_getts on double fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_getts (cert, "test-b", &t) < 0 && errno == EINVAL,
        "sigcert_meta_getts on boolean fails with EINVAL");

    /* Destroy NULL
     */
    lives_ok ({sigcert_destroy (NULL);},
        "sigcert_destroy cert=NULL doesn't crash");

    sigcert_destroy (cert);
}

void test_sign_cert (void)
{
    struct sigcert *cert, *cert2;
    struct sigcert *ca;
    const char *name;
    char *s;

    if (!(cert = sigcert_create ()))
        BAIL_OUT ("sigcert_create: %s", strerror (errno));
    if (sigcert_meta_sets (cert, "username", "itsme") < 0)
        BAIL_OUT ("meta_sets failed");
    if (!(ca = sigcert_create ()))
        BAIL_OUT ("sigcert_create: %s", strerror (errno));

    /* Verification of an unsigned cert fails.
     */
    errno = 0;
    ok (sigcert_verify_cert (ca, cert) < 0 && errno == EINVAL,
        "sigcert_verify_cert fails with EINVAL");

    /* CA signs and verifies cert.
     */
    ok (sigcert_sign_cert (ca, cert) == 0,
        "sigcert_sign_cert works");
    ok (sigcert_verify_cert (ca, cert) == 0,
        "sigcert_verify_cert works");

    /* Verification of a signed cert still works after JSON serialization.
     */
    s = sigcert_json_dumps (cert);
    ok (s != NULL,
        "sigcert_json_dumps works on signed cert");
    cert2 = sigcert_json_loads (s);
    ok (cert2 != NULL,
        "sigcert_json_loads works on signed cert");
    ok (sigcert_verify_cert (ca, cert2) == 0,
        "sigcert_verify_cert works after JSON dumps/loads");
    sigcert_destroy (cert2);

    /* Verification of a signed cert still works after TOML serialization.
     */
    name = new_keypath ("test");
    ok (sigcert_store (cert, name) == 0,
        "sigcert_store works on signed cert");
    cert2 = sigcert_load (name, false);
    ok (cert2 != NULL,
        "sigcert_load works on signed cert");
    ok (sigcert_verify_cert (ca, cert2) == 0,
        "sigcert_verify_cert works on reloaded cert");
    sigcert_destroy (cert2);
    cleanup_keypath ("test");
    cleanup_keypath ("test.pub");

    /* Verification of a signed but modified cert fails.
     */
    ok (sigcert_meta_sets (cert, "username", "noitsme") == 0,
        "sigcert_meta_sets changes signed cert");
    errno = 0;
    ok (sigcert_verify_cert (ca, cert) < 0 && errno == EINVAL,
        "sigcert_verify_cert fails with EINVAL");

    sigcert_destroy (cert);
    sigcert_destroy (ca);
}

static const char *goodcert_pub =
  "[metadata]\n"
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4mNjnwbC/0gTYAG2d9yReTJwc=\"\n";

static const char *goodcert =
  "[curve]\n"
  "    secret-key = \"j+UF7qPPkehuwBz/DZjW4NE4lKcdXG+eM+828J30UwOr3vgDNB1IA+C/fauW2XnPdGVv730JGig3lAiRRYzqVA==\"\n";

static const char *badcerts_secret[] = {
  // 0 - no secret key
  "[curve]\n",

  // 1 - no curve section
  "\n",

  // 2 - invalid base64 secret-key
  "[curve]\n"
  "    secret-key = \"j+UF7qPPkehuwBz/DZjW4NE4lKcdXG+eM+8.8J30UwOr3vgDNB1IA+C/fauW2XnPdGVv730JGig3lAiRRYzqVA==\"\n",

  // 3 - short secret-key (but valid base64)
  "[curve]\n"
  "    secret-key = \"j+UF7qPPkehuwBz/DZjW4NE4lKcdXG+eM+828J30UwOr3vgDNB1IA+C/fauW2XnPdGVv730JGig3lAiRRYzq\n",

  // 4 - long secret-key (but valid base64)
  "[curve]\n"
  "    secret-key = \"j+UF7qPPkehuwBz/DZjW4NE4lKcdXG+eM+828J30UwOr3vgDNB1IA+C/fauW2XnPdGVv730JGig3lAiRRYzqVGE=\n",

};
static const int badcerts_secret_count = sizeof (badcerts_secret)
                                        / sizeof (badcerts_secret[0]);

static const char *badcerts[] = {
  // 0 - no public key
  "[metadata]\n"
  "[curve]\n",

  // 1 - no metadata section
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4mNjnwbC/0gTYAG2d9yReTJwc=\"\n"
  "    signature = \"lemKu7wjG/KpLFaOPVt+axUvMzXRf/GoE7vQJDPH7iePXwKrDmOLZ3uQq4qQATOUHRuSDerdWyM6qokyKziiAg==\"\n",

  // 2 - no curve section
  "[metadata]\n",

  // 3 - invalid base64 public-key
  "[metadata]\n"
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4m.jnwbC/0gTYAG2d9yReTJwc=\"\n",

  // 4 - short public-key (but valid base64)
  "[metadata]\n"
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4mNjnwbC/0gTYAG2d9yReTJw==\"\n",

  // 5 - long public-key (but valid base64)
  "[metadata]\n"
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4mNjnwbC/0gTYAG2d9yReTJwdh\"\n",

  // 6 - invalid base64 signature
  "[metadata]\n"
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4mNjnwbC/0gTYAG2d9yReTJwc=\"\n"
  "    signature = \"lemKu7wjG/KpLFaOPVt+axUvMzXRf/G.E7vQJDPH7iePXwKrDmOLZ3uQq4qQATOUHRuSDerdWyM6qokyKziiAg==\"\n",

  // 6 - short signature (but valid base64)
  "[metadata]\n"
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4mNjnwbC/0gTYAG2d9yReTJwc=\"\n"
  "    signature = \"lemKu7wjG/KpLFaOPVt+axUvMzXRf/GoE7vQJDPH7iePXwKrDmOLZ3uQq4qQATOUHRuSDerdWyM6qokyKzii\"\n",

  // 7 - long signature (but valid base64)
  "[metadata]\n"
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4mNjnwbC/0gTYAG2d9yReTJwc=\"\n"
  "    signature = \"lemKu7wjG/KpLFaOPVt+axUvMzXRf/GoE7vQJDPH7iePXwKrDmOLZ3uQq4qQATOUHRuSDerdWyM6qokyKziiAmE=\"\n",
};
static const int badcerts_count = sizeof (badcerts) / sizeof (badcerts[0]);

void create_file_content (const char *path, const void *content, size_t size)
{
    FILE *fp = fopen (path, "w+");
    if (!fp)
        BAIL_OUT ("%s: fopen: %s", path, strerror (errno));
    if (fwrite (content, size, 1, fp) != 1)
        BAIL_OUT ("%s: fwrite: %s", path, strerror (errno));
    if (fclose (fp) < 0)
        BAIL_OUT ("%s: fclose: %s", path, strerror (errno));
}

bool check_public_file (const char *content)
{
    struct sigcert *cert;
    bool valid = false;
    const char *name;

    name = new_keypath ("test.pub");
    create_file_content (name, content, strlen (content));

    name = new_keypath ("test");
    if ((cert = sigcert_load (name, false))) {
        sigcert_destroy (cert);
        valid = true;
    }
    cleanup_keypath ("test");
    cleanup_keypath ("test.pub");
    return valid;
}

bool check_secret_file (const char *content)
{
    struct sigcert *cert;
    bool valid = false;
    const char *name;

    name = new_keypath ("test.pub");
    create_file_content (name, goodcert_pub, strlen (goodcert_pub));

    name = new_keypath ("test");
    create_file_content (name, content, strlen (content));

    if ((cert = sigcert_load (name, true))) {
        sigcert_destroy (cert);
        valid = true;
    }
    cleanup_keypath ("test");
    cleanup_keypath ("test.pub");
    return valid;
}

void test_badcert (void)
{
    int i;

    ok (check_public_file (goodcert_pub) == true,
        "sanity check good public cert");
    ok (check_secret_file (goodcert) == true,
        "sanity check good secret cert");

    for (i = 0; i < badcerts_count; i++) {
        ok (check_public_file (badcerts[i]) == false,
            "sigcert_load failed on bad public cert %d", i);
    }
    for (i = 0; i < badcerts_secret_count; i++) {
        ok (check_secret_file (badcerts_secret[i]) == false,
            "sigcert_load failed on bad secret cert %d", i);
    }
}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);
    new_scratchdir ();

    test_meta ();
    test_load_store ();
    test_sign_verify();
    test_json_load_dump_sign ();
    test_json_load_dump ();
    test_corner ();
    test_sign_cert ();
    test_badcert ();

    cleanup_scratchdir ();
    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */
