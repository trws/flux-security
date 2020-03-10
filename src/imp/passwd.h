/************************************************************\
 * Copyright 2020 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_IMP_PASSWD_H
#define HAVE_IMP_PASSWD_H 1

#include <pwd.h>
#include <sys/types.h>

/*
 *  Return a copy of the passwd entry for UID
 *  Caller must free with passwd_destroy()
 */
struct passwd * passwd_from_uid (uid_t uid);

/*
 *  Free memory for a copy of passwd entry created by passwd_from_uid
 */
void passwd_destroy (struct passwd *pw);

#endif /* !HAVE_IMP_PASSWD_H */
