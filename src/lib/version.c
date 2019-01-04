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
#include "config.h"
#endif

#include "version.h"

const char *flux_security_version_string (void)
{
    return FLUX_SECURITY_VERSION_STRING;
}

int flux_security_version (int *major, int *minor, int *patch)
{
    if (major)
        *major = FLUX_SECURITY_VERSION_MAJOR;
    if (minor)
        *minor = FLUX_SECURITY_VERSION_MINOR;
    if (patch)
        *patch = FLUX_SECURITY_VERSION_PATCH;
    return FLUX_SECURITY_VERSION_HEX;
}


/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
