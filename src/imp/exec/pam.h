/************************************************************\
 * Copyright 2022 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_IMP_PAM_H_
#define HAVE_IMP_PAM_H_ 1

int pam_setup (const char *user);

void pam_finish ();

#endif  // HAVE_IMP_PAM_H_
