/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
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
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <errno.h>

#include "imp_log.h"
#include "sudosim.h"

const char * sudo_user_name (void)
{
    if (getuid() == 0)
        return (getenv ("SUDO_USER"));
    return (NULL);
}

bool sudo_is_active (void)
{
    return (sudo_user_name() != NULL);
}

int sudo_simulate_setuid (void)
{
    const char *user = NULL;

    /*  Ignore SUDO_USER unless real UID is 0. We're then fairly sure this
     *   process was run under sudo, or someone with privileges wants to
     *   simulate running under sudo.
     */
    if ((user = sudo_user_name ())) {
        struct passwd *pwd = getpwnam (user);

        /*  Fail in the abnormal condition that SUDO_USER is not found.
         */
        if (pwd == NULL)
            return (-1);

        /*  O/w, set real UID/GID to the SUDO_USER credentials so it
         *   appears that this process is setuid.
         */
        if (setresgid (pwd->pw_gid, -1, -1) < 0) {
            imp_warn ("sudosim: setresgid: %s", strerror (errno));
            return (-1);
        }
        if (setresuid (pwd->pw_uid, -1, -1) < 0) {
            imp_warn ("sudosim: setresuid: %s", strerror (errno));
            return (-1);
        }
    }
    return (0);
}

/*
 * vi: ts=4 sw=4 expandtab
 */
