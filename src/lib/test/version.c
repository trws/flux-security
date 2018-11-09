#include "src/lib/version.h"
#include "src/libtap/tap.h"

#include <string.h>

int main (int argc, char *argv[])
{
    const char *s;
    int a,b,c,d;
    char vs[32];

    plan (NO_PLAN);

    d = flux_security_version (&a, &b, &c);
    ok (d == (a<<16 | b<<8 | c),
        "flux_security_version returned sane value");

    lives_ok ({flux_security_version (NULL, NULL, NULL);},
        "flux_security_version NULL, NULL, NULL doesn't crash");

    snprintf (vs, sizeof (vs), "%d.%d.%d", a,b,c);
    s = flux_security_version_string ();
    ok (s != NULL && !strncmp (s, vs, strlen (vs)),
        "flux_security_version_string returned expected string");
    diag (s);



    done_testing();
    return (0);
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */

