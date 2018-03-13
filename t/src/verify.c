/* verify.c - verify signed content on stdin
 *
 * Usage: verify <input >output
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "src/lib/context.h"
#include "src/lib/sign.h"

const char *prog = "verify";

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

static int read_all (void *buf, int bufsz)
{
    int n;
    int count = 0;
    do {
        if ((n = read (STDIN_FILENO, (char *)buf + count, bufsz - count)) < 0)
            die ("read stdin: %s", strerror (errno));
        count += n;
    } while (n > 0 && count < bufsz);
    if (n > 0)
        die ("input buffer exceeded");
    return count;
}

int main (int argc, char **argv)
{
    flux_security_t *ctx;
    char buf[8192];
    int buflen;
    int64_t userid;
    const char *payload;
    int payloadsz;

    if (argc != 1)
        die ("Usage: verify <input >output");

    if (!(ctx = flux_security_create (0)))
        die ("flux_security_create");
    if (flux_security_configure (ctx, getenv ("FLUX_IMP_CONFIG_PATTERN")) < 0)
        die ("flux_security_configure: %s", flux_security_last_error (ctx));

    buflen = read_all (buf, sizeof (buf) - 1);
    buf[buflen] = '\0';

    if (flux_sign_unwrap (ctx, buf, (const void **)&payload, &payloadsz,
                          &userid, 0) < 0)
        die ("flux_sign_unwrap: %s", flux_security_last_error (ctx));

    fwrite (payload, payloadsz, 1, stdout);
    if (ferror (stdout))
        die ("write stdout failed");

    flux_security_destroy (ctx);

    return 0;
}

/* vi: ts=4 sw=4 expandtab
 */
