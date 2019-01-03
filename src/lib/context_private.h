/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef _FLUX_SECURITY_CONTEXT_PRIVATE_H
#define _FLUX_SECURITY_CONTEXT_PRIVATE_H

#include <stdarg.h>
#include "src/libutil/cf.h"

/* Capture errno in ctx->errno, and an error message in ctx->error.
 * If 'fmt' is non-NULL, build message; otherwise use strerror (errno).
 */
void security_error (flux_security_t *ctx, const char *fmt, ...);

/* Retrieve config object by 'key', entire config if key == NULL.
 * Returns the object (do not free), or NULL on error.
 */
const cf_t *security_get_config (flux_security_t *ctx, const char *key);

/* Set config object 'cf' as security handle configuration.
 * 'cf' is copied internally and any existing configuration is destroyed.
 */
int security_set_config (flux_security_t *ctx, const cf_t *cf);

#endif /* !_FLUX_SECURITY_CONTEXT_PRIVATE_H */
