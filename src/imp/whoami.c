/*****************************************************************************\
 *  Copyright (c) 2017 Lawrence Livermore National Security, LLC.  Produced at
 *  the Lawrence Livermore National Laboratory (cf, AUTHORS, DISCLAIMER.LLNS).
 *  LLNL-CODE-658032 All rights reserved.
 *
 *  This file is part of the Flux resource manager framework.
 *  For details, see https://github.com/flux-framework.
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the Free
 *  Software Foundation; either version 2 of the license, or (at your option)
 *  any later version.
 *
 *  Flux is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the IMPLIED WARRANTY OF MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the terms and conditions of the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *  See also:  http://www.gnu.org/licenses/
\*****************************************************************************/

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
