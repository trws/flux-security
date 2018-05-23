/* getpwuid.c - LD_PRELOAD version of getpwuid() that uses TEST_PASSWD_FILE
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <pwd.h>
#include <errno.h>

struct passwd *getpwuid (uid_t uid)
{
    const char *filename;
    static char buf[4096];
    static struct passwd pw;
    struct passwd *pwp = NULL;

    if ((filename = getenv ("TEST_PASSWD_FILE"))) {
        FILE *f;
        if ((f = fopen (filename, "r"))) {
            while (fgetpwent_r (f, &pw, buf, sizeof (buf), &pwp) == 0) {
                if (pwp->pw_uid == uid)
                    break;
            }
            (void)fclose (f);
        }
    }
    else
        getpwuid_r (uid, &pw, buf, sizeof (buf), &pwp);

    if (pwp == NULL)
        errno = ENOENT;
    return pwp;
}

/* vi: ts=4 sw=4 expandtab
 */
