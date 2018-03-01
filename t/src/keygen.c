/* keygen.c - generate signing keys
 *
 * Usage: keygen path
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "src/libca/sigcert.h"

const char *prog = "keygen";

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

int main (int argc, char **argv)
{
    struct sigcert *cert;
    const char *certname;

    if (argc != 2)
        die ("Usage: keygen path");
    certname = argv[1];

    if (!(cert = sigcert_create ()))
        die ("sigcert_create: %s", strerror (errno));
    if (sigcert_store (cert, certname) < 0)
        die ("sigcert_store: %s", strerror (errno));
    sigcert_destroy (cert);

    return 0;
}

/* vi: ts=4 sw=4 expandtab
 */
