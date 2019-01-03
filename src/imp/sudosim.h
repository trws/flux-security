/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_SUDOSIM_H
#define HAVE_SUDOSIM_H 1

#include <stdbool.h>

/*  If current process was run under sudo, return the user name as recorded
 *   in the SUDO_USER environment variable. Return NULL otherwise.
 */
const char * sudo_user_name (void);

/*  Return true if it appears the current process is running under sudo, i.e.
 *   real UID is 0, and SUDO_USER environment variable is set.
 */
bool sudo_is_active (void);

/*  If running under sudo by evidence of real UID == 0 and SUDO_USER set,
 *   adapt process credentials to simulate a setuid program. That is,
 *   set the real UID/GID to that of SUDO_USER and leave effective/saved
 *   UIDs as root.
 *
 *  Returns 0 on success or if SUDO not active (in which case nothing was
 *   done), or < 0 if some failure occurred (should be fatal).
 */
int sudo_simulate_setuid (void);

#endif /* !HAVE_SUDOSIM_H */
