/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "src/libutil/kv.h"
#include "src/libutil/cf.h"
#include "src/libca/sigcert.h"
#include "src/libca/ca.h"

#include "imp_log.h"
#include "imp_state.h"
#include "impcmd.h"
#include "privsep.h"

/* Create a cert from 'cert' prefix in 'kv'.
 * On success, return cert.  On failure, return NULL with errno set.
 */
static struct sigcert *get_cert_from_kv (const struct kv *kv)
{
    struct kv *cert_kv;
    const char *buf;
    int len;
    struct sigcert *cert = NULL;

    if (!(cert_kv = kv_split (kv, "cert")))
        goto done;
    if (kv_encode (cert_kv, &buf, &len) < 0)
        goto done;
    cert = sigcert_decode (buf, len);
done:
    kv_destroy (cert_kv);
    return cert;
}

/* Add cert to kv under 'cert' prefix.
 * On success, return 0. On failure, return -1 with errno set.
 */
static int add_cert_to_kv (struct kv *kv, const struct sigcert *cert)
{
    struct kv *cert_kv = NULL;
    const char *buf;
    int len;
    int rc = -1;

    if (sigcert_encode (cert, &buf, &len) < 0)
        goto done;
    if (!(cert_kv = kv_decode (buf, len)))
        goto done;
    rc = kv_join (kv, cert_kv, "cert");
done:
    kv_destroy (cert_kv);
    return rc;
}

/* Sign 'cert' with the CA cert, and emit to stdout.
 * The cert userid is set to the real uid used to execute the imp.
 * The TTL is set to the configured maximum.
 * The location of the CA cert is obtained from the [ca] configuration.
 */
static void sign_cert (cf_t *conf, struct sigcert *cert)
{
    struct ca *ca;
    const cf_t *cf;
    ca_error_t error;
    int64_t ttl = 0;            // use configured maximum
    int64_t userid = getuid (); // sign as real userid

    if (!conf)
        imp_die (1, "casign: no configuration");
    if (!(cf = cf_get_in (conf, "ca")))
        imp_die (1, "casign: no [ca] configuration");
    if (!(ca = ca_create (cf, error)))
        imp_die (1, "casign: ca_create: %s", error);
    if (ca_load (ca, true, error) < 0)
        imp_die (1, "casign: ca_load: %s", error);
    if (ca_sign (ca, cert, 0, ttl, userid, error) < 0)
        imp_die (1, "casign: ca_sign: %s", error);
    if (sigcert_fwrite_public (cert, stdout) < 0)
        imp_die (1, "casign: write stdout: %s", strerror (errno));
    ca_destroy (ca);
}

int imp_casign_privileged (struct imp_state *imp, const struct kv *kv)
{
    struct sigcert *cert;

    if (!(cert = get_cert_from_kv (kv)))
        imp_die (1, "casign: decode cert: %s", strerror (errno));
    sign_cert (imp->conf, cert);
    sigcert_destroy (cert);
    return (0);
}

int imp_casign_unprivileged (struct imp_state *imp, struct kv *kv)
{
    struct sigcert *cert;

    if (!(cert = sigcert_fread_public (stdin)))
        imp_die (1, "casign: decode cert: %s", strerror (errno));

    if (imp->ps) {
        if (add_cert_to_kv (kv, cert) < 0)
            imp_die (1, "casign: encode cert: %s", strerror (errno));
        if (privsep_write_kv (imp->ps, kv) < 0)
            imp_die (1, "casign: failed to communicate with privsep parent");
    }
    /* N.B. for testing, if the IMP isn't installed setuid, try the signing
     * operation without privilege.  It will fail if the CA cert cannot be
     * accessed, as would normally be the case in a real installation.
     */
    else {
        imp_warn ("casign: imp is not installed setuid, proceeding anyway...");
        sign_cert (imp->conf, cert);
    }

    sigcert_destroy (cert);
    return (0);
}

/* vi: ts=4 sw=4 expandtab
 */
