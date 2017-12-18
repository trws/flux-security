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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

#include "base64.h"
#include "kv.h"

#define KV_CHUNK 4096

struct kv {
    char *buf;
    int bufsz;
    int len;
    char *base64;
};

void kv_destroy (struct kv *kv)
{
    if (kv) {
        int saved_errno = errno;
        free (kv->buf);
        free (kv->base64);
        free (kv);
        errno = saved_errno;
    }
}

static struct kv *kv_create_from (const char *buf, int len)
{
    struct kv *kv;

    if (len < 0 || (len > 0 && !buf)) {
        errno = EINVAL;
        return NULL;
    }
    if (!(kv = calloc (1, sizeof (*kv))))
        return NULL;
    if (len > 0) {
        if (!(kv->buf = malloc (len))) {
            kv_destroy (kv);
            return NULL;
        }
        memcpy (kv->buf, buf, len);
        kv->bufsz = kv->len = len;
    }
    return kv;
}

struct kv *kv_create (void)
{
    return kv_create_from (NULL, 0);
}

struct kv *kv_copy (const struct kv *kv)
{
    if (!kv) {
        errno = EINVAL;
        return NULL;
    }
    return kv_create_from (kv->buf, kv->len);
}

bool kv_equal (const struct kv *kv1, const struct kv *kv2)
{
    if (!kv1 || !kv2)
        return false;
    if (kv1->len != kv2->len)
        return false;
    if (memcmp (kv1->buf, kv2->buf, kv1->len) != 0)
        return false;
    return true;
}

/* Grow kv buffer until it can accommodate 'needsz' new characters.
 */
static int kv_expand (struct kv *kv, int needsz)
{
    char *new;
    while (kv->bufsz - kv->len < needsz) {
        if (!(new = realloc (kv->buf, kv->bufsz + KV_CHUNK)))
            return -1;
        kv->buf = new;
        kv->bufsz += KV_CHUNK;
    }
    return 0;
}

static bool valid_key (const char *key)
{
    if (!key || *key == '\0')
        return false;
    return true;
}

static const char *kv_find (const struct kv *kv, const char *key)
{
    const char *k = NULL;

    while ((k = kv_next (kv, k))) {
        if (!strcmp (key, k))
            return k;
    }
    return NULL;
}

/* Return length, not to exceed maxlen, of entry consisting of key\0value\0
 * Return -1 on invalid entry.
 */
static int entry_length (const char *entry, int maxlen)
{
    int keylen;
    int vallen;

    keylen = strnlen (entry, maxlen);
    if (keylen == 0 || keylen == maxlen)
        return -1;
    entry += keylen + 1;
    maxlen -= keylen + 1;
    vallen = strnlen (entry, maxlen);
    if (vallen == 0 || vallen == maxlen)
        return -1;
    return keylen + vallen + 2;
}

int kv_delete (struct kv *kv, const char *key)
{
    const char *entry;
    int entry_offset;
    int entry_len;

    if (!kv || !valid_key (key)) {
        errno = EINVAL;
        return -1;
    }
    if (!(entry = kv_find (kv, key))) {
        errno = ENOENT;
        return -1;
    }
    entry_offset = entry - kv->buf;
    entry_len = entry_length (entry, kv->len - entry_offset);
    assert (entry_len >= 0);
    memmove (kv->buf + entry_offset,
             kv->buf + entry_offset + entry_len,
             kv->len - entry_offset - entry_len);
    kv->len -= entry_len;
    return 0;
}

int kv_put (struct kv *kv, const char *key, const char *val)
{
    if (!kv || !valid_key (key) || !val) {
        errno = EINVAL;
        return -1;
    }
    if (kv_delete (kv, key) < 0) {
        if (errno != ENOENT)
            return -1;
    }
    int keylen = strlen (key);
    int vallen = strlen (val);
    if (kv_expand (kv, keylen + vallen + 2) < 0) // key\0val\0
        return -1;
    strncpy (&kv->buf[kv->len], key, keylen + 1);
    kv->len += keylen + 1;
    strncpy (&kv->buf[kv->len], val, vallen + 1);
    kv->len += vallen + 1;
    return 0;
}

int kv_putf (struct kv *kv, const char *key, const char *fmt, ...)
{
    va_list ap;
    char *val;
    int rc;

    if (!fmt) { // N.B. kv and key are checked by kv_put
        errno = EINVAL;
        return -1;
    }
    va_start (ap, fmt);
    rc = vasprintf (&val, fmt, ap);
    va_end (ap);
    if (rc < 0) {
        errno = ENOMEM;
        return -1;
    }
    if (kv_put (kv, key, val) < 0) {
        int saved_errno = errno;
        free (val);
        errno = saved_errno;
        return -1;
    }
    free (val);
    return 0;
}

const char *kv_next (const struct kv *kv, const char *key)
{
    int entry_len;
    int entry_offset;

    if (!kv || kv->len == 0)
        return NULL;
    if (!key)
        return kv->buf;
    if (key < kv->buf || key > kv->buf + kv->len)
        return NULL;
    entry_offset = key - kv->buf;
    entry_len = entry_length (key, kv->len - entry_offset);
    if (entry_len < 0 || entry_offset + entry_len == kv->len)
        return NULL;
    return key + entry_len;
}

const char *kv_val (const char *key)
{
    if (!key)
        return NULL;
    return key + strlen (key) + 1;
}

int kv_get (const struct kv *kv, const char *key, const char **val)
{
    const char *entry;

    if (!kv || !valid_key (key)) {
        errno = EINVAL;
        return -1;
    }
    if (!(entry = kv_find (kv, key))) {
        errno = ENOENT;
        return -1;
    }
    if (val)
        *val = kv_val (entry);
    return 0;
}

int kv_getf (const struct kv *kv, const char *key, const char *fmt, ...)
{
    va_list ap;
    const char *val;
    int rc;

    if (!fmt) {
        errno = EINVAL;
        return -1;
    }
    if (kv_get (kv, key, &val) < 0)
        return -1;
    va_start (ap, fmt);
    rc = vsscanf (val, fmt, ap);
    va_end (ap);
    return rc;
}

/* Validate a just-decoded kv buffer.
 */
static int kv_check_integrity (struct kv *kv)
{
    int nullcount;
    int i;
    const char *key = NULL;

    /* properly terminated
     */
    if (kv->len > 0 && kv->buf[kv->len - 1] != '\0')
        goto inval;

    /* even number of nulls
     */
    nullcount = 0;
    for (i = 0; i < kv->len; i++) {
        if (kv->buf[i] == '\0')
            nullcount++;
    }
    if (nullcount % 2 != 0)
        goto inval;

    /* nonzero key and val lengths
     */
    while ((key = kv_next (kv, key))) {
        const char *val = kv_val (key);
        if (strlen (key) == 0 || !val || strlen (val) == 0)
            goto inval;
    }

    return 0;
inval:
    errno = EINVAL;
    return -1;
}

int kv_raw_encode (const struct kv *kv, const char **buf, int *len)
{
    if (!kv || !buf || !len) {
        errno = EINVAL;
        return -1;
    }
    *buf = kv->buf;
    *len = kv->len;
    return 0;
}

struct kv *kv_raw_decode (const char *buf, int len)
{
    struct kv *kv;

    if (!(kv = kv_create_from (buf, len)))
        return NULL;
    if (kv_check_integrity (kv) < 0) {
        kv_destroy (kv);
        return NULL;
    }
    return kv;
}

const char *kv_base64_encode (const struct kv *kv)
{
    char *dst;
    int dstlen;
    int rc;

    if (!kv) {
        errno = EINVAL;
        return NULL;
    }
    dstlen = base64_encode_length (kv->len);
    if (!(dst = malloc (dstlen)))
        return NULL;
    rc = base64_encode_block (dst, &dstlen, kv->buf, kv->len);
    assert (rc == 0);

    free (kv->base64);
    /* N.B. cast away const here to allow this function to return
     * a const value owned by struct kv.  This does not change the "value"
     * per se, so it is safe.
     */
    ((struct kv *)(kv))->base64 = dst;
    return kv->base64;
}

struct kv *kv_base64_decode (const char *buf, int len)
{
    char *dst;
    int dstlen;
    struct kv *kv;

    if (len < 0 || (len > 0 && buf == NULL)) {
        errno = EINVAL;
        return NULL;
    }
    dstlen = base64_decode_length (len);
    if (!(dst = malloc (dstlen)))
        return NULL;
    if (base64_decode_block (dst, &dstlen, buf, len) < 0) {
        free (dst);
        errno = EINVAL;
        return NULL;
    }
    if (!(kv = kv_raw_decode (dst, dstlen))) {
        int saved_errno = errno;
        free (dst);
        errno = saved_errno;
        return NULL;
    }
    free (dst);
    return kv;
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
