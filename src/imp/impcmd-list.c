/*****************************************************************************\
 *  Copyright (c) 2017 Lawrence Livermore National Security, LLC.  Produced at
 *  the Lawrence Livermore National Laboratory (cf, AUTHORS, DISCLAIMER.LLNS).
 *  LLNL-CODE-658032 All rights reserved.
 *
 *  This file is part of the Flux resource manager framework.
 *  For details, see https://github.com/flux-framework.
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the Free
 *  Software Foundation; either version 2 of the license, or (at your option)
 *  any later version.
 *
 *  Flux is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the IMPLIED WARRANTY OF MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the terms and conditions of the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *  See also:  http://www.gnu.org/licenses/
\*****************************************************************************/

#include "src/libutil/kv.h"
#include "impcmd.h"

extern int imp_cmd_version (struct imp_state *imp, struct kv *);
extern int imp_whoami_unprivileged (struct imp_state *imp, struct kv *);
extern int imp_whoami_privileged (struct imp_state *imp, struct kv *);

/*  List of supported imp commands, curated by hand for now.
 *   For each named command, the `child_fn` runs unprivileged and the
 *   `parent_fn` runs privileged. The child function communicates to
 *   the parent using privsep_write/read.
 *
 */
struct impcmd impcmd_list[] = {
	{ "version",
	  imp_cmd_version, NULL },
	{ "whoami",
	  imp_whoami_unprivileged,
      imp_whoami_privileged },
	{ NULL, NULL, NULL}
};

/* vi: ts=4 sw=4 expandtab
 */
