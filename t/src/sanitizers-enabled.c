/************************************************************\
 * Copyright 2019 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/*
 * Exit with 0 if flux-security built with --enable-sanitizers,
 *  o/w exit nonzero.
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

int main (int ac, char **av)
{
#if SANITIZERS_ENABLED
    return 0;
#else  /* !SANITIZERS_ENABLED */
    return 1;
#endif /* SANITIZERS_ENABLED  */
}

/* vi: ts=4 sw=4 expandtab
 */
