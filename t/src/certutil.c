/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/* certutil.c - get/put cert metadata
 *
 * Usage: certutil certname get key
 *        certutil certname put key [type:]value
 *
 * Possible type indicators are
 *   s = string (default)
 *   i = int64
 *   d = double
 *   b = boolean
 *   t = timestamp
 *
 * N.B. timestamps are input/output in seconds-since-epoch localtime form,
 * for easy manipulation in sharness tests, comparisons with TTL's, etc..
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "src/libca/sigcert.h"

const char *prog = "certutil";

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
    fprintf (stderr, "Usage: certutil certname get key [type]\n"
                     "   or: certutil certname put key [type:]value\n");
    exit (1);
}

/* Get key from cert metadata and display.
 */
void get_meta (const char *certname, const char *key, const char *type)
{
    struct sigcert *cert;

    if (!type)
        type = "s";
    if (!(cert = sigcert_load (certname, false)))
        die ("load %s: %s", certname, strerror (errno));
    switch (type[0]) {
        case 's': {
            const char *s;
            if (sigcert_meta_get (cert, key, SM_STRING, &s) < 0)
                die ("sigcert_meta_get: %s", strerror (errno));
            printf ("%s\n", s);
            break;
        }
        case 'i': {
            int64_t i;
            if (sigcert_meta_get (cert, key, SM_INT64, &i) < 0)
                die ("sigcert_meta_get: %s", strerror (errno));
            printf ("%lld\n", (long long int)i);
            break;
        }
        case 'd': {
            double d;
            if (sigcert_meta_get (cert, key, SM_DOUBLE, &d) < 0)
                die ("sigcert_meta_get: %s", strerror (errno));
            printf ("%lf\n", d);
            break;
        }
        case 'b': {
            bool b;
            if (sigcert_meta_get (cert, key, SM_BOOL, &b) < 0)
                die ("sigcert_meta_get: %s", strerror (errno));
            printf ("%s\n", b ? "true" : "false");
            break;
        }
        case 't': {
            time_t t;
            if (sigcert_meta_get (cert, key, SM_TIMESTAMP, &t) < 0)
                die ("sigcert_meta_get: %s", strerror (errno));
            printf ("%d\n", (int)t);
            break;
        }
        default:
            die ("unknown type indicator '%c'", type[0]);
            break;
    }
    sigcert_destroy (cert);
}

/* Put key=value to cert.
 * The type: prefix determines the type of the value.
 */
void put_meta (const char *certname, const char *key, const char *value)
{
    struct sigcert *cert;
    char type[2] = "s";

    if (strlen (value) >= 2 && value[1] == ':') {
        type[0] = value[0];
        value += 2;
    }
    if (!(cert = sigcert_load (certname, false)))
        die ("load %s: %s", certname, strerror (errno));
    switch (type[0]) {
        case 's': {
            if (sigcert_meta_set (cert, key, SM_STRING, value) < 0)
                die ("sigcert_meta_set: %s", strerror (errno));
            break;
        }
        case 'i': {
            int64_t i = strtoll (value, NULL, 10);
            if (sigcert_meta_set (cert, key, SM_INT64, i) < 0)
                die ("sigcert_meta_set: %s", strerror (errno));
            break;
        }
        case 'd': {
            double d = strtod (value, NULL);
            if (sigcert_meta_set (cert, key, SM_DOUBLE, d) < 0)
                die ("sigcert_meta_set: %s", strerror (errno));
            break;
        }
        case 'b': {
            bool b = !strcmp (value, "false") ? false : true;
            if (sigcert_meta_set (cert, key, SM_BOOL, b) < 0)
                die ("sigcert_meta_set: %s", strerror (errno));
            break;
        }
        case 't': {
            time_t t = strtol (value, NULL, 10);
            if (sigcert_meta_set (cert, key, SM_TIMESTAMP, t) < 0)
                die ("sigcert_meta_set: %s", strerror (errno));
            break;
        }
        default:
            die ("unknown type indicator '%c'", type[0]);
            break;
    }

    if (sigcert_store (cert, certname) < 0)
        die ("store %s: %s", certname, strerror (errno));
    sigcert_destroy (cert);
}

int main (int argc, char **argv)
{
    if ((argc == 4 || argc == 5) && !strcmp (argv[2], "get"))
        get_meta (argv[1], argv[3], argc == 5 ? argv[4] : NULL);
    else if ((argc == 5 && !strcmp (argv[2], "put")))
        put_meta (argv[1], argv[3], argv[4]);
    else
        usage ();
    return 0;
}

/* vi: ts=4 sw=4 expandtab
 */
