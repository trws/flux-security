/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_IMPCMD_H
#define HAVE_IMPCMD_H 1

#include "src/libutil/kv.h"
#include "imp_state.h"

typedef int (*imp_cmd_f) (struct imp_state *imp, struct kv *kv);

struct impcmd {
    const char *name;
    imp_cmd_f child_fn;
    imp_cmd_f parent_fn;
};

/*  Return unprivileged child version of IMP command with `name`, or NULL
 *   if no such command found.
 */
imp_cmd_f imp_cmd_find_child (const char *name);

/*  Return privileged parent version of IMP command with `name`, or NULL
 *   if no such command found.
 */
imp_cmd_f imp_cmd_find_parent (const char *name);

#endif /* !HAVE_IMPCMD_H */
