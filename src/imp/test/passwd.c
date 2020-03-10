/************************************************************\
 * Copyright 2020 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#include <stdio.h>
#include <errno.h>
#include "passwd.h"

#include "src/libtap/tap.h"

int main (void)
{
    struct passwd *pwd;

    /* check passwd_destroy() on NULL doesn't segfault */
    lives_ok ({passwd_destroy (NULL);},
        "passwd_destroy (NULL) doesn't segfault");

    /* Get known UID 0 */
    if (!(pwd = passwd_from_uid (0)))
        BAIL_OUT ("passwd_from_uid() failed");
    ok (pwd->pw_uid == 0,
        "pwd->pw_uid is correct");
    is (pwd->pw_name, "root",
        "passwd_from_uid() returned correct entry for root");
    passwd_destroy (pwd);

    ok (!(pwd = passwd_from_uid (-1)),
        "passwd_from_uid() fails on invalid uid");
    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */
