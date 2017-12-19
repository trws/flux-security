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
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <time.h>
#include <assert.h>

#include "kv.h"

#define KV_CHUNK 4096

struct kv {
    char *buf;
    int bufsz;
    int len;
};

void kv_destroy (struct kv *kv)
{
    if (kv) {
        int saved_errno = errno;
        free (kv->buf);
        free (kv);
        errno = saved_errno;
    }
}

/* Create kv object from 'buf' and 'len'.
 * If len == 0, create an empty object.
 * Returns object on success, NULL on failure with errno set.
 */
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
 * Returns 0 on success, -1 on failure with errno set.
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

/* Look up entry by key (and type if type != KV_UNKNOWN).
 * Returns entry on success, NULL on failure with errno set.
 */
static const char *kv_find (const struct kv *kv, const char *key,
                            enum kv_type type)
{
    const char *entry = NULL;

    if (!kv || !valid_key (key)) {
        errno = EINVAL;
        return NULL;
    }
    while ((entry = kv_next (kv, entry))) {
        if (!strcmp (key, entry)) {
            if (type == KV_UNKNOWN || kv_typeof (entry) == type)
                return entry;
            break;
        }
    }
    errno = ENOENT;
    return NULL;
}

/* Return length, not to exceed maxlen, of entry consisting of key\0Tvalue\0
 * Return -1 on invalid entry.
 */
static int entry_length (const char *entry, int maxlen)
{
    int keylen;
    int vallen; // including T

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

    if (!(entry = kv_find (kv, key, KV_UNKNOWN)))
        return -1;
    entry_offset = entry - kv->buf;
    entry_len = entry_length (entry, kv->len - entry_offset);
    assert (entry_len >= 0);
    memmove (kv->buf + entry_offset,
             kv->buf + entry_offset + entry_len,
             kv->len - entry_offset - entry_len);
    kv->len -= entry_len;
    return 0;
}

/* Put typed key=val (val is in string form).
 * If key already exists, remove it first.
 * Return 0 on success, -1 on failure with errno set.
 */
static int kv_put (struct kv *kv, const char *key,
                   enum kv_type type, const char *val)
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
    if (kv_expand (kv, keylen + vallen + 3) < 0) // key\0Tval\0
        return -1;
    strncpy (&kv->buf[kv->len], key, keylen + 1);
    kv->len += keylen + 1;
    kv->buf[kv->len++] = type;
    strncpy (&kv->buf[kv->len], val, vallen + 1);
    kv->len += vallen + 1;
    return 0;
}

int kv_put_string (struct kv *kv, const char *key, const char *val)
{
    return kv_put (kv, key, KV_STRING, val);
}

int kv_put_int64 (struct kv *kv, const char *key, int64_t val)
{
    char s[64];
    if (snprintf (s, sizeof (s), "%" PRIi64, val) >= sizeof (s)) {
        errno = EINVAL;
        return -1;
    }
    return kv_put (kv, key, KV_INT64, s);
}

int kv_put_double (struct kv *kv, const char *key, double val)
{
    char s[64];
    if (snprintf (s, sizeof (s), "%f", val) >= sizeof (s)) {
        errno = EINVAL;
        return -1;
    }
    return kv_put (kv, key, KV_DOUBLE, s);
}

int kv_put_bool (struct kv *kv, const char *key, bool val)
{
    return kv_put (kv, key, KV_BOOL, val ? "true" : "false");
}

int kv_put_timestamp (struct kv *kv, const char *key, time_t val)
{
    char s[64];
    struct tm tm;

    if (val < 0 || !gmtime_r (&val, &tm)
                || strftime (s, sizeof (s), "%FT%TZ", &tm) == 0) {
        errno = EINVAL;
        return -1;
    }
    return kv_put (kv, key, KV_TIMESTAMP, s);
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

const char *kv_val_string (const char *key)
{
    if (!key)
        return "";
    return &key[strlen (key) + 2];
}

int64_t kv_val_int64 (const char *key)
{
    return strtoll (kv_val_string (key), NULL, 10);
}

double kv_val_double (const char *key)
{
    return strtod (kv_val_string (key), NULL);
}

bool kv_val_bool (const char *key)
{
    const char *s = kv_val_string (key);
    if (!strcmp (s, "false") || strlen (s) == 0)
        return false;
    else
        return true;
}

time_t kv_val_timestamp (const char *key)
{
    struct tm tm;
    time_t t;
    const char *s = kv_val_string (key);
    if (!strptime (s, "%FT%TZ", &tm) || (t = timegm (&tm)) < 0)
        return 0;
    return t;
}

enum kv_type kv_typeof (const char *key)
{
    if (!key)
        return KV_UNKNOWN;
    enum kv_type type = key[strlen (key) + 1];
    switch (type) {
        case KV_STRING:
        case KV_INT64:
        case KV_DOUBLE:
        case KV_BOOL:
        case KV_TIMESTAMP:
            return type;
        default:
            return KV_UNKNOWN;
    }
}

int kv_get_string (const struct kv *kv, const char *key, const char **val)
{
    const char *entry = kv_find (kv, key, KV_STRING);
    if (!entry)
        return -1;
    if (val)
        *val = kv_val_string (entry);
    return 0;
}

int kv_get_int64 (const struct kv *kv, const char *key, int64_t *val)
{
    const char *entry = kv_find (kv, key, KV_INT64);
    if (!entry)
        return -1;
    if (val)
        *val = kv_val_int64 (entry);
    return 0;
}

int kv_get_double (const struct kv *kv, const char *key, double *val)
{
    const char *entry = kv_find (kv, key, KV_DOUBLE);
    if (!entry)
        return -1;
    if (val)
        *val = kv_val_double (entry);
    return 0;
}

int kv_get_bool (const struct kv *kv, const char *key, bool *val)
{
    const char *entry = kv_find (kv, key, KV_BOOL);
    if (!entry)
        return -1;
    if (val)
        *val = kv_val_bool (entry);
    return 0;
}

int kv_get_timestamp (const struct kv *kv, const char *key, time_t *val)
{
    const char *entry = kv_find (kv, key, KV_TIMESTAMP);
    if (!entry)
        return -1;
    if (val)
        *val = kv_val_timestamp (entry);
    return 0;
}

/* Validate a just-decoded kv buffer.
 * Return 0 on success, -1 on failure with errno set.
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

    /* nonzero key length
     * value has valid type hint char
     */
    while ((key = kv_next (kv, key))) {
        if (strlen (key) == 0)
            goto inval;
        if (kv_typeof (key) == KV_UNKNOWN)
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

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
