/************************************************************\
 * Copyright 2022 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#include "pam.h"

#include <stddef.h>
#include <stdio.h>

#include "imp_log.h"

#include <security/pam_appl.h>
#include <security/pam_misc.h>

static pam_handle_t *pam_h = NULL;

int pam_setup (const char *user)
{
    struct pam_conv conv = {misc_conv, NULL};
    int rc;

    if ((rc = pam_start ("flux",
                         user,
                         &conv,
                         &pam_h)) != PAM_SUCCESS) {
        imp_warn ("pam_start: %s", pam_strerror (NULL, rc));
        goto fail1;
    }
    if ((rc = pam_set_item (pam_h, PAM_USER, user)) != PAM_SUCCESS) {
        imp_warn ("pam_set_item USER: %s", pam_strerror (pam_h, rc));
        goto fail2;
    }
    if ((rc = pam_set_item (pam_h, PAM_RUSER, user)) != PAM_SUCCESS) {
        imp_warn ("pam_set_item RUSER: %s", pam_strerror (pam_h, rc));
        goto fail2;
    }
    if ((rc = pam_setcred (pam_h, PAM_ESTABLISH_CRED)) != PAM_SUCCESS) {
        imp_warn ("pam_setcred: %s", pam_strerror (pam_h, rc));
        goto fail2;
    }
    if ((rc = pam_open_session (pam_h, 0)) != PAM_SUCCESS) {
        imp_warn ("pam_open_session: %s", pam_strerror (pam_h, rc));
        goto fail3;
    }
    return 0;

fail3:
    pam_setcred (pam_h, PAM_DELETE_CRED);

fail2:
    pam_end (pam_h, rc);

fail1:
    pam_h = NULL;
    return rc == PAM_SUCCESS ? 0 : -1;
}

void pam_finish ()
{
    int rc = 0;
    if (pam_h != NULL) {
        if ((rc = pam_close_session (pam_h, 0)) != PAM_SUCCESS) {
            imp_warn ("pam_close_session: %s", pam_strerror (pam_h, rc));
        }
        if ((rc = pam_setcred (pam_h, PAM_DELETE_CRED)) != PAM_SUCCESS) {
            imp_warn ("pam_setcred: %s", pam_strerror (pam_h, rc));
        }
        if ((rc = pam_end (pam_h, rc)) != PAM_SUCCESS) {
            imp_warn ("pam_end: %s", pam_strerror (pam_h, rc));
        }
        pam_h = NULL;
    }
}

/*
 *  vi: sw=4 ts=4 expandtab
 */
