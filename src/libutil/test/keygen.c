/* keygen - generate signing keys */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include "sigcert.h"

void die (const char *fmt, ...)
{
    va_list ap;
    char msg[1024];

    va_start (ap, fmt);
    (void)vsnprintf (msg, sizeof (msg), fmt, ap);
    va_end (ap);
    fprintf (stderr, "keygen: %s%s%s\n",
             msg, errno > 0 ? ": " : "",
                  errno > 0 ? strerror (errno) : "");
    exit (1);
}

/* Generate a new cert and store it to target_path.
 * If it exists, it will be overwritten.
 * Paths leading up to the key files must exist.
 */
void generate_cert (const char *target_path)
{
    struct sigcert *cert;
    time_t t;

    if (!(cert = sigcert_create ()))
        die ("sigcert_create");
    if (time (&t) == (time_t)-1)
        die ("time");
    if (sigcert_meta_set (cert, "create-time", SM_TIMESTAMP, t) < 0)
        die ("sigcert_meta_set create-time");
    if (sigcert_meta_set (cert, "userid", SM_INT64, (int64_t)getuid ()) < 0)
        die ("sigcert_meta_set userid");
    fprintf (stderr, "keygen: updating %s\n", target_path);
    if (sigcert_store (cert, target_path) < 0)
        die ("sigcert_store");
    sigcert_destroy (cert);
}

/* Sign cert at 'target_path' with cert at 'signer_path'.
 * Add some made up metadata as stand in for CA info.
 */
void sign_cert (const char *signer_path, const char *target_path)
{
    struct sigcert *cert1;
    struct sigcert *cert2;
    time_t t;
    int64_t userid;

    if (!(cert1 = sigcert_load (signer_path, true)))
        die ("load %s", signer_path);
    if (!(cert2 = sigcert_load (target_path, false)))
        die ("load %s", target_path);

    if (sigcert_meta_get (cert1, "userid", SM_INT64, &userid) < 0)
        die ("sigcert_meta_get userid");
    if (sigcert_meta_set (cert2, "ca-userid", SM_INT64, userid) < 0)
        die ("sigcert_meta_set ca-userid");
    if (time (&t) == (time_t)-1)
        die ("time");
    if (sigcert_meta_set (cert2, "ca-signed-time", SM_TIMESTAMP, t) < 0)
        die ("sigcert_meta_set ca-signed-time");

    if (sigcert_sign_cert (cert1, cert2) < 0)
        die ("sigcert_sign_cert");
    fprintf (stderr, "keygen: updating %s\n", target_path);
    if (sigcert_store (cert2, target_path) < 0)
        die ("store %s", target_path);
    sigcert_destroy (cert1);
    sigcert_destroy (cert2);
}

/* Verify that cert at 'target_path' was signed by cert at 'signer_path'.
 */
void verify_cert (const char *signer_path, const char *target_path)
{
    struct sigcert *cert1;
    struct sigcert *cert2;

    if (!(cert1 = sigcert_load (signer_path, false)))
        die ("load %s", signer_path);
    if (!(cert2 = sigcert_load (target_path, false)))
        die ("load %s", target_path);
    if (sigcert_verify_cert (cert1, cert2) < 0)
        fprintf (stderr, "signature verifcation failed\n");
    else
        fprintf (stderr, "signature verification succeeded\n");
    sigcert_destroy (cert1);
    sigcert_destroy (cert2);
}

void usage (void)
{
    fprintf (stderr, "Usage: keygen [--sign=PATH] [--verify=PATH] [PATH]\n");
}

#define OPTIONS "+hs:v:"
static const struct option longopts[] = {
    {"help",                  no_argument,          0, 'h'},
    {"sign",                  required_argument,    0, 's'},
    {"verify",                required_argument,    0, 'v'},
    { 0, 0, 0, 0 },
};

int main (int argc, char *argv[])
{
    char default_path[PATH_MAX + 1];
    const char *target_path = NULL;
    const char *signer_path = NULL;
    const char *verifier_path = NULL;
    struct passwd *pw;
    int ch;

    while ((ch = getopt_long (argc, argv, OPTIONS, longopts, NULL)) != -1) {
        switch (ch) {
            case 's':   // --sign=PATH
                signer_path = optarg;
                break;
            case 'v':   // --verify=PATH
                verifier_path = optarg;
                break;
            default:
                usage ();
                break;
        }
    }
    if (optind < argc)
        target_path = argv[optind++];
    if (optind < argc)
        usage ();

    if (!target_path) {
        if (!(pw = getpwuid (getuid ())))
            die ("who are you?");
        if (snprintf (default_path, PATH_MAX + 1,
                      "%s/.flux/curve/sig", pw->pw_dir) >= PATH_MAX + 1)
            die ("key path buffer overflow");
        target_path = default_path;
    }

    if (signer_path)
        sign_cert (signer_path, target_path);
    else if (verifier_path)
        verify_cert (verifier_path, target_path);
    else
        generate_cert (target_path);

    return 0;
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
