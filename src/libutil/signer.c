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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "base64.h"
#include "sigcert.h"
#include "kv.h"
#include "signer.h"

/* max allowable clock drift (seconds) in case ctime exceeds wall clock
 */
const int64_t max_clock_drift = 300;

struct signer {
    void *buf;                  // Buffer for wrap/unwrap results is grown as
    int bufsz;                  // needed, and not freed until signer_destroy().
};


/* Update 'e' if non-NULL.
 * If 'fmt' is non-NULL, build message; otherwise use strerror (errno).
 */
static void signer_error (signer_error_t e, const char *fmt, ...)
{
    if (e) {
        size_t sz = sizeof (ca_error_t);
        int saved_errno = errno;
        if (fmt) {
            va_list ap;
            va_start (ap, fmt);
            vsnprintf (e, sz, fmt, ap);
            va_end (ap);
        }
        else
            snprintf (e, sz, "%s", strerror (errno));
        errno = saved_errno;
    }
}

struct signer *signer_create (void)
{
    struct signer *signer;
    if (!(signer = calloc (1, sizeof (*signer))))
        return NULL;
    return signer;
}

void signer_destroy (struct signer *signer)
{
    if (signer) {
        int saved_errno = errno;
        free (signer->buf);
        free (signer);
        errno = saved_errno;
    }
}

/* Grow *buf to newsz if *bufsz is less than that.
 * Return 0 on success, -1 on failure with errno set.
 */
static int grow_buf (void **buf, int *bufsz, int newsz)
{
    if (*bufsz < newsz) {
        void *new = realloc (*buf, newsz);
        if (!new)
            return -1;
        *buf = new;
        *bufsz = newsz;
    }
    return 0;
}

/* Decode a 'kv' that was serialized and base64 encoded.
 * It need not be NULL terminated.  Caller must kv_destroy the result.
 * Return kv on success, NULL on failure with errno set.
 */
static struct kv *decode_kv_base64 (const char *src, int srclen)
{
    char *dst;
    int dstlen;
    struct kv *kv = NULL;
    int saved_errno;

    dstlen = base64_decode_length (srclen);
    if (!(dst = malloc (dstlen)))
        return NULL;
    if (base64_decode_block (dst, &dstlen, src, srclen) < 0) {
        errno = EINVAL;
        goto done;
    }
    if (!(kv = kv_decode (dst, dstlen)))
        goto done;
done:
    saved_errno = errno;
    free (dst);
    errno = saved_errno;
    return kv;
}

/* Add cert to 'kv' under prefix 'key'.
 * Return 0 on success, -1 on failure with errno set.
 */
static int put_cert (struct kv *kv, const char *key, const struct sigcert *cert)
{
    const char *s;
    int len;
    struct kv *kv_cert;
    int rc;

    if (sigcert_encode (cert, &s, &len) < 0)
        return -1;
    if (!(kv_cert = kv_decode (s, len)))
        return -1;
    rc = kv_join (kv, kv_cert, key);
    kv_destroy (kv_cert);
    return rc;
}

/* Get cert from 'kv' under prefix 'key'.
 * Put the result in 'cp' (caller must kv_destroy).
 * Return 0 on success, -1 on failure with errno set.
 */
static int get_cert (struct kv *kv, const char *key, struct sigcert **cp)
{
    struct kv *kv_cert;
    const char *s;
    int len;
    struct sigcert *cert;
    int rc = -1;

    if (!(kv_cert = kv_split (kv, key)))
        return -1;
    if (kv_encode (kv_cert, &s, &len) < 0)
        goto done;
    if (!(cert = sigcert_decode (s, len)))
        goto done;
    *cp = cert;
    rc = 0;
done:
    kv_destroy (kv_cert);
    return rc;
}

/* Encode HEADER (base64) to *buf, growing as needed.
 * Return 0 on success, -1 on failure with errno set.
 */
static int encode_header (const struct sigcert *cert,
                          time_t ctime, time_t xtime,
                          void **buf, int *bufsz)
{
    struct kv *kv;
    const char *src;
    int srclen;
    int dstlen;
    int rc = -1;

    if (!(kv = kv_create ()))
        return -1;
    if (kv_put (kv, "ctime", KV_TIMESTAMP, ctime) < 0)
        goto done;
    if (kv_put (kv, "xtime", KV_TIMESTAMP, xtime) < 0)
        goto done;
    if (put_cert (kv, "cert.", cert) < 0)
        goto done;
    if (kv_encode (kv, &src, &srclen) < 0)
        goto done;
    dstlen = base64_encode_length (srclen);
    if (grow_buf (buf, bufsz, dstlen) < 0)
        goto done;
    rc = base64_encode_block (*buf, &dstlen, src, srclen);
    assert (rc == 0);
done:
    kv_destroy (kv);
    return rc;
}

/* Decode HEADER portion of HEADER.PAYLOAD.SIGNATURE
 * Caller must sigcert_destory cert assigned to 'certp'.
 * Return 0 on success, -1 on failure with errno set.
 */
static int decode_header (const char *s, struct sigcert **certp,
                          time_t *ctimep, time_t *xtimep, signer_error_t e)
{
    struct kv *kv;
    struct sigcert *cert;
    time_t ctime;
    time_t xtime;
    char *p;
    int rc = -1;

    if (!(p = strchr (s, '.'))) {
        errno = EINVAL;
        signer_error (e, "header delimiter");
        return -1;
    }
    if (!(kv = decode_kv_base64 (s, p - s))) {
        signer_error (e, "header error decoding");
        return -1;
    }
    if (kv_get (kv, "ctime", KV_TIMESTAMP, &ctime) < 0) {
        errno = EINVAL;
        signer_error (e, "header has no ctime");
        goto done;
    }
    if (kv_get (kv, "xtime", KV_TIMESTAMP, &xtime) < 0) {
        errno = EINVAL;
        signer_error (e, "header has no xtime");
        goto done;
    }
    if (get_cert (kv, "cert.", &cert) < 0) {
        errno = EINVAL;
        signer_error (e, "header has no cert");
        goto done;
    }
    *certp = cert;
    *ctimep = ctime;
    *xtimep = xtime;
    rc = 0;
done:
    kv_destroy (kv);
    return rc;
}

/* Append ".PAYLOAD" (as a base64 string) to '*buf', growing as necessary.
 * Return 0 on success, -1 on failure with errno set.
 */
static int append_payload (const void *pay, int paysz, void **buf, int *bufsz)
{
    int len;
    int dstlen;
    char *dst;
    int rc;

    len = strlen (*buf);
    dstlen = base64_encode_length (paysz);
    if (grow_buf (buf, bufsz, dstlen + len + 1) < 0)
        return -1;
    dst = (char *)*buf + len;
    *dst++ = '.';
    rc = base64_encode_block (dst, &dstlen, pay, paysz);
    assert (rc == 0);
    return 0;
}

/* Decode payload portion of HEADER.PAYLOAD.SIGNATURE to '*buf',
 * growing as necessary.
 * Return payload size on success, -1 on failure with errno set.
 */
static int decode_payload (const char *s, void **buf, int *bufsz)
{
    char *p;
    char *q;
    int dstlen;
    int srclen;
    char *src;

    if (!(p = strchr (s, '.')) || !(q = strchr (p + 1, '.'))) {
        errno = EINVAL;
        return -1;
    }
    srclen = q - p - 1;
    src = p + 1;
    dstlen = base64_decode_length (srclen);
    if (grow_buf (buf, bufsz, dstlen) < 0)
        return -1;
    if (base64_decode_block (*buf, &dstlen, src, srclen) < 0) {
        errno = EINVAL;
        return -1;
    }
    return dstlen;
}

const char *signer_wrap (struct signer *signer,
                         const struct sigcert *cert, int64_t ttl,
                         const void *pay, int paysz, signer_error_t e)
{
    time_t ctime;
    time_t xtime;

    if (!signer || !cert || paysz < 0 || (!pay && paysz != 0) || ttl < 0) {
        errno = EINVAL;
        goto error;
    }
    /* N.B. could check ttl against 'max-sign-ttl' in cert.  For now allow
     * requested ttl.  signer_unwrap() will fail if it exceeds cert's max.
     */
    if (time (&ctime) < 0)
        goto error;
    xtime = ctime + ttl;

    /* Encode HEADER as base64 string.
     * Use signer->buf as storage so user doesn't have to manage.
     * As a consequence, it is only valid until next wrap/unwrap/destroy.
     */
    if (encode_header (cert, ctime, xtime, &signer->buf, &signer->bufsz) < 0) {
        signer_error (e, "error encoding header: %s", strerror (errno));
        goto error_nomsg;
    }
    /* Append .PAYLOAD (base64).
     */
    if (append_payload (pay, paysz, &signer->buf, &signer->bufsz) < 0) {
        signer_error (e, "error appending payload: %s", strerror (errno));
        goto error_nomsg;
    }
    /* Append .SIGNATURE (base64).
     */
    if (grow_buf (&signer->buf, &signer->bufsz,
                  sigcert_sign_length (signer->buf)) < 0) {
        signer_error (e, "error signing: %s", strerror (errno));
        goto error_nomsg;
    }
    if (sigcert_sign (cert, signer->buf, signer->bufsz) < 0) {
        signer_error (e, "error signing: %s", strerror (errno));
        goto error_nomsg;
    }
    return signer->buf;
error:
    signer_error (e, NULL);
error_nomsg:
    return NULL;
}

int signer_unwrap (struct signer *signer, const struct ca *ca, const char *s,
                   const void **pay, int *paysz, int64_t *userid,
                   signer_error_t e)
{
    struct sigcert *cert = NULL;
    time_t ctime;
    time_t xtime;
    time_t now;
    int64_t cert_userid;
    int64_t max_ttl;
    int len;
    ca_error_t ca_error;

    if (!signer || !ca || !s) {
        errno = EINVAL;
        goto error;
    }
    /* Decode HEADER portion of 's'.
     */
    if (decode_header (s, &cert, &ctime, &xtime, e) < 0)
        goto error_nomsg;
    /* Check cert for revocation, expiration, proper CA signature,
     * and get cert's userid and max_ttl.
     */
    if (ca_verify (ca, cert, &cert_userid, &max_ttl, ca_error) < 0) {
        signer_error (e, "ca_verify: %s", ca_error);
        goto error_nomsg;
    }
    /* Fail if wall clock has reached or exceeded xtime.
     */
    if (time (&now) < 0)
        goto error;
    if (ctime > now) {           // decrease [ctime:xtime] if ctime in future
        int64_t offset = ctime - now;
        if (offset > max_clock_drift) {
            errno = ETIMEDOUT;
            signer_error (e, "signature ctime is %llds in the future", offset);
            goto error_nomsg;
        }
        ctime -= offset;
        xtime -= offset;
    }
    if (xtime > ctime + max_ttl) // reduce xtime if cert max_ttl exceeded
        xtime = ctime + max_ttl;
    if (now >= xtime) {
        errno = ETIMEDOUT;
        signer_error (e, "signature expired %llds ago", now - xtime);
        goto error_nomsg;
    }
    /* Fail if cert cannot validate HEADER.PAYLOAD string.
     * N.B. sigcert_verify() checks .SIGNATURE suffix against rest of string.
     */
    if (sigcert_verify (cert, s) < 0) {
        signer_error (e, "signature verification failed");
        goto error_nomsg;
    }
    /* Decode PAYLOAD portion of 's'.
     * Use signer->buf as storage so user doesn't have to manage.
     * As a consequence, it is only valid until next wrap/unwrap/destroy.
     */
    if ((len = decode_payload (s, &signer->buf, &signer->bufsz)) < 0) {
        signer_error (e, "error decoding payload: %s", strerror (errno));
        goto error_nomsg;
    }
    if (userid)
        *userid = cert_userid;
    if (pay)
        *pay = signer->buf;
    if (paysz)
        *paysz = len;
    sigcert_destroy (cert);
    return 0;
error:
    signer_error (e, NULL);
error_nomsg:
    sigcert_destroy (cert);
    return -1;
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
