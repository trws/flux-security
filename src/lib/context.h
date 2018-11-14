/*****************************************************************************\
 *  Copyright (c) 2018 Lawrence Livermore National Security, LLC.  Produced at
 *  the Lawrence Livermore National Laboratory (cf, AUTHORS, DISCLAIMER.LLNS).
 *  LLNL-CODE-658032 All rights reserved.
 *
 *  This file is part of the Flux resource manager framework.
 *  For details, see https://github.com/flux-framework.
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public License as published
 *  by the Free Software Foundation; either version 2.1 of the license,
 *  or (at your option) any later version.
 *
 *  Flux is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the IMPLIED WARRANTY OF MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the terms and conditions of the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *  See also:  http://www.gnu.org/licenses/
\*****************************************************************************/

#ifndef _FLUX_SECURITY_CONTEXT_H
#define _FLUX_SECURITY_CONTEXT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct flux_security flux_security_t;

typedef void (*flux_security_free_f)(void *arg);

flux_security_t *flux_security_create (int flags);
void flux_security_destroy (flux_security_t *ctx);

const char *flux_security_last_error (flux_security_t *ctx);
int flux_security_last_errnum (flux_security_t *ctx);

int flux_security_configure (flux_security_t *ctx, const char *pattern);

int flux_security_aux_set (flux_security_t *ctx, const char *name,
		           void *data, flux_security_free_f freefun);

void *flux_security_aux_get (flux_security_t *ctx, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* !_FLUX_SECURITY_CONTEXT_H */
