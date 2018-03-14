/* uidlookup.c - exercise getpwuid
 *
 * Usage: uidlookup uid
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
#include <pwd.h>

#include "src/lib/context.h"
#include "src/lib/sign.h"

const char *prog = "uidlookup";

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
    struct passwd *pw;

    if (argc != 2)
        die ("Usage: %s uid", prog);
    if (!(pw = getpwuid (strtoul (argv[1], NULL, 10))))
        die ("getpwuid: %s", strerror (errno));
    printf ("%s\n", pw->pw_dir);

    return 0;
}

/* vi: ts=4 sw=4 expandtab
 */
