/*****************************************************************************\
 *  Copyright (c) 2018 Lawrence Livermore National Security, LLC.  Produced at
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
#  include <config.h>
#endif /* HAVE_CONFIG_H */
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "context.h"
#include "context_private.h"
#include "sign.h"
#include "sign_mech.h"

static const char *op_sign (flux_security_t *ctx, const char *input, int flags)
{
    return "none";
}

static int op_verify (flux_security_t *ctx, const char *input,
                      const struct kv *header, int flags)
{
    int len = strlen (input);
    int siglen = strlen (".none");
    int64_t userid;
    int64_t real_userid = getuid ();

    if (kv_get (header, "userid", KV_INT64, &userid) < 0
                                    || userid != real_userid) {
        errno = EINVAL;
        security_error (ctx, "sign-none-verify: header userid %ld != real %ld",
                        (long)userid, (long)real_userid);
        return -1;
    }
    if (len < siglen || strcmp (input + len - siglen, ".none") != 0) {
        security_error (ctx, "sign-none-verify: signature invalid");
        return -1;
    }
    return 0;
}

const struct sign_mech sign_mech_none = {
    .name = "none",
    .init = NULL,
    .prep = NULL,
    .sign = op_sign,
    .verify = op_verify,
};

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
