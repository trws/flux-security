/* ca.c - CA utility
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "src/libutil/cf.h"
#include "src/libca/sigcert.h"
#include "src/libca/ca.h"

extern const char *imp_get_config_pattern (void);

const char *prog = "ca";

static void die (const char *fmt, ...)
{
    va_list ap;
    char buf[256];

    va_start (ap, fmt);
    (void)vsnprintf (buf, sizeof (buf), fmt, ap);
    va_end (ap);
    fprintf (stderr, "%s: %s\n", prog, buf);
    exit (1);
}

static void usage (void)
{
    fprintf (stderr,
"Usage: ca keygen\n"
"   or: ca revoke uuid\n"
"   or: ca verify path\n");
}

static struct ca *init_ca (void)
{
    const char *pattern = imp_get_config_pattern ();
    cf_t *conf;
    const cf_t *conf_ca;
    struct cf_error e;
    struct ca *ca;
    ca_error_t error;

    assert (pattern != NULL);
    if (!(conf = cf_create ()))
        die ("cf_create: %s", strerror (errno));
    if (cf_update_glob (conf, pattern, &e) < 0)
        die ("%s::%d: %s", e.filename, e.lineno, e.errbuf);
    if (!(conf_ca = cf_get_in (conf, "ca")))
        die ("no [ca] configuration");
    if (!(ca = ca_create (conf_ca, error)))
        die ("ca_create: %s", error);

    cf_destroy (conf);

    return ca;
}

/* Add 'uuid' to the CA revocation directory.
 */
static void revoke (const char *uuid)
{
    struct ca *ca = init_ca ();
    ca_error_t error;

    if (ca_revoke (ca, uuid, error) < 0)
        die ("ca_revoke: %s", error);

    ca_destroy (ca);
}

/* Generate new CA cert, writing to the configured path.
 */
static void keygen (void)
{
    struct ca *ca = init_ca ();
    ca_error_t error;

    if (ca_keygen (ca, 0, 0, error) < 0)
        die ("ca_keygen: %s", error);
    if (ca_store (ca, error) < 0)
        die ("ca_store: %s", error);

    ca_destroy (ca);
}

/* Verify that a cert was signed by the CA and has not been revoked.
 */
static void verify (const char *path)
{
    struct ca *ca = init_ca ();
    ca_error_t error;
    struct sigcert *cert;
    int64_t userid;

    if (ca_load (ca, false, error) < 0)
        die ("ca_load: %s", error);
    if (!(cert = sigcert_load (path, false)))
        die ("sigcert_load: %s", strerror (errno));
    if (ca_verify (ca, cert, &userid, NULL, error) < 0)
        die ("ca_verify: %s", error);
    printf ("%lld\n", (long long)userid);
    sigcert_destroy (cert);

    ca_destroy (ca);
}


int main (int argc, char **argv)
{
    if (argc == 2 && !strcmp (argv[1], "keygen"))
        keygen ();
    else if (argc == 3 && !strcmp (argv[1], "revoke"))
        revoke (argv[2]);
    else if (argc == 3 && !strcmp (argv[1], "verify"))
        verify (argv[2]);
    else
        usage ();

    return 0;
}

/* vi: ts=4 sw=4 expandtab
 */
