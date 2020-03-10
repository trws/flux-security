/************************************************************\
 * Copyright 2020 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "passwd.h"

static struct passwd * passwd_copy (struct passwd *arg)
{
    struct passwd *pwd = calloc (1, sizeof (*pwd));
    if (pwd) {
        pwd->pw_uid = arg->pw_uid;
        pwd->pw_gid = arg->pw_gid;
        if (!(pwd->pw_name = strdup (arg->pw_name))
            || !(pwd->pw_passwd = strdup (arg->pw_passwd))
            || !(pwd->pw_gecos = strdup (arg->pw_gecos))
            || !(pwd->pw_dir = strdup (arg->pw_dir))
            || !(pwd->pw_shell = strdup (arg->pw_shell))) {
            passwd_destroy (pwd);
            return NULL;
        }
    }
    return pwd;
}

struct passwd * passwd_from_uid (uid_t uid)
{
    struct passwd *pwd = NULL;
    if (!(pwd = getpwuid (uid)))
        return NULL;
    return passwd_copy (pwd);
}

void passwd_destroy (struct passwd *pwd)
{
    if (pwd) {
        free (pwd->pw_name);
        free (pwd->pw_passwd);
        free (pwd->pw_gecos);
        free (pwd->pw_dir);
        free (pwd->pw_shell);
        free (pwd);
    }
}

/*
 * vi: ts=4 sw=4 expandtab
 */
