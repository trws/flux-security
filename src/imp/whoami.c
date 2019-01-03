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
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "src/libutil/kv.h"

#include "imp_log.h"
#include "imp_state.h"
#include "impcmd.h"
#include "privsep.h"

static void print_ids (const char *prefix)
{
    printf ("%s: uid=%ju euid=%ju gid=%ju egid=%ju\n",
            prefix, (uintmax_t) getuid(), (uintmax_t) geteuid(),
            (uintmax_t) getgid(), (uintmax_t) getegid());
}

int imp_whoami_privileged (struct imp_state *imp __attribute__ ((unused)),
                           struct kv *kv __attribute__ ((unused)))
{
    print_ids ("flux-imp: privileged");
    return (0);
}

int imp_whoami_unprivileged (struct imp_state *imp, struct kv *kv)
{
    /* Send kv with `cmd="whoami"` to parent */
    if (imp->ps && privsep_write_kv (imp->ps, kv) < 0)
        imp_die (1, "whoami: failed to communicate with privsep parent");
    print_ids ("flux-imp: unprivileged");
    return (0);
}

/* vi: ts=4 sw=4 expandtab
 */
