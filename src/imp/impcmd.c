/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#include <stdio.h>
#include <string.h>

#include "impcmd.h"

extern struct impcmd impcmd_list[];

static struct impcmd * imp_cmd_lookup (const char *name)
{
    struct impcmd *cmd = &impcmd_list[0];
    while (cmd->name != NULL) {
        if (strcmp (name, cmd->name) == 0)
            return (cmd);
        cmd++;
    }
    return (NULL);
}

imp_cmd_f imp_cmd_find_child (const char *name)
{
    struct impcmd *cmd = imp_cmd_lookup (name);
    if (cmd)
        return (cmd->child_fn);
    return (NULL);
}

imp_cmd_f imp_cmd_find_parent (const char *name)
{
    struct impcmd *cmd = imp_cmd_lookup (name);
    if (cmd)
        return (cmd->parent_fn);
    return (NULL);
}

/* vi: ts=4 sw=4 expandtab
 */
