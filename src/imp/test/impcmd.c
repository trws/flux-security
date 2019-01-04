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
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "impcmd.h"

#include "src/libtap/tap.h"

static int test_cmd (struct imp_state *imp __attribute__ ((unused)),
                     struct kv *kv __attribute__ ((unused)))
{
    return 0;
}

static int test_cmd_privileged (struct imp_state *imp __attribute__ ((unused)),
                     struct kv *kv __attribute__ ((unused)))
{
    return 0;
}

struct impcmd impcmd_list[] =
{
    { "test",
      test_cmd, test_cmd_privileged },
    { "test2",
      test_cmd, NULL },
    { NULL, NULL, NULL }
};

int main (void)
{
    imp_cmd_f cmd;
    plan (NO_PLAN);

    ok ((cmd = imp_cmd_find_child ("noexist")) == NULL,
        "imp_cmd_find_child returns NULL on nonexistent function");
    ok ((cmd = imp_cmd_find_parent ("noexist")) == NULL,
        "imp_cmd_find_parent returns NULL on nonexistent function");
    ok ((cmd = imp_cmd_find_child ("test")) != NULL,
        "imp_cmd_find_child finds 'test' cmd");
    ok (cmd == test_cmd, "imp_cmd_find_child returned correct function");
    ok ((cmd = imp_cmd_find_parent ("test")) != NULL,
        "imp_cmd_find_parent finds 'test' subcommand");
    ok (cmd == test_cmd_privileged,
        "imp_cmd_find_parent returned correct function");
    ok ((cmd = imp_cmd_find_child ("test2")) != NULL,
        "imp_cmd_find_child finds 'test2' cmd");
    ok ((cmd = imp_cmd_find_parent ("test2")) == NULL,
        "imp_cmd_find_parent returns NULL for 'test2' cmd");

    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */
