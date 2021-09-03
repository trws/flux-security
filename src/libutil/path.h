/************************************************************\
 * Copyright 2021 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef _UTIL_PATH_H
#define _UTIL_PATH_H

#include <stdbool.h>

struct path_error {
    char text [128];
};

/*  Return true if file at `path` and its parent directory have secure
 *   ownership and permissions. If false, error->text will be filled
 *   in with a textual reason the file is not secure.
 */
bool path_is_secure (const char *path, struct path_error *error);

#endif /* !_UTIL_PATH_H */

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
