/************************************************************\
 * Copyright 2020 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_IMP_EXEC_USER_H
#define HAVE_IMP_EXEC_USER_H 1
/*
 *  Switch process to new UID/GID with supplementary group initialization
 */
void imp_switch_user (uid_t uid);

#endif /* !HAVE_IMP_EXEC_USER_H */
