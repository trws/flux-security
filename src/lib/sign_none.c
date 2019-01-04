/************************************************************\
 * Copyright 2018 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

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

static char *op_sign (flux_security_t *ctx,
                            const char *input, int inputsz, int flags)
{
    char *cpy;
    if (!(cpy = strdup ("none"))) {
        security_error (ctx, NULL);
        return NULL;
    }
    return cpy;
}

static int op_verify (flux_security_t *ctx, const struct kv *header,
                      const char *input, int inputsz,
                      const char *signature, int flags)
{
    int64_t userid;
    int64_t real_userid = getuid ();

    if (kv_get (header, "userid", KV_INT64, &userid) < 0
                                    || userid != real_userid) {
        errno = EINVAL;
        security_error (ctx, "sign-none-verify: header userid %ld != real %ld",
                        (long)userid, (long)real_userid);
        return -1;
    }
    if (strcmp (signature, "none") != 0) {
        errno = EINVAL;
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
