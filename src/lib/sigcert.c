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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <sodium.h>
#include <jansson.h>

#include "src/libtomlc99/toml.h"
#include "src/libutil/base64.h"
#include "sigcert.h"

/* Define some handy types for fixed length keys and their base64 encodings.
 * N.B. macro versions of base64_encode_length() and base64_decode_length()
 * were defined so these types can be declared in a struct or on the stack.
 * Also, the raw types must be long enough to receive base64_decode_length()
 * bytes in place, hence the BASE64_DECODE_MAXLEN() macro below.
 */
#define BASE64_ENCODE_LENGTH(srclen) (((((srclen) + 2) / 3) * 4) + 1)
#define BASE64_DECODE_LENGTH(srclen) (((((srclen) + 3) / 4) * 3) + 1)

#define BASE64_DECODE_MAXLEN(dstlen) \
             (BASE64_DECODE_LENGTH(BASE64_ENCODE_LENGTH(dstlen)))

typedef uint8_t public_t[BASE64_DECODE_MAXLEN(crypto_sign_PUBLICKEYBYTES)];
typedef uint8_t secret_t[BASE64_DECODE_MAXLEN(crypto_sign_SECRETKEYBYTES)];
typedef uint8_t sign_t[BASE64_DECODE_MAXLEN(crypto_sign_BYTES)];

typedef char public_base64_t[BASE64_ENCODE_LENGTH(crypto_sign_PUBLICKEYBYTES)];
typedef char secret_base64_t[BASE64_ENCODE_LENGTH(crypto_sign_SECRETKEYBYTES)];
typedef char sign_base64_t[BASE64_ENCODE_LENGTH(crypto_sign_BYTES)];


#define FLUX_SIGCERT_MAGIC 0x2349c0ed
struct flux_sigcert {
    int magic;

    public_t public_key;
    secret_t secret_key;
    sign_t signature;

    json_t *meta;

    bool secret_valid;
    bool signature_valid;
};

void flux_sigcert_destroy (struct flux_sigcert *cert)
{
    if (cert) {
        int saved_errno = errno;
        assert (cert->magic == FLUX_SIGCERT_MAGIC);
        json_decref (cert->meta);
        memset (cert->public_key, 0, crypto_sign_PUBLICKEYBYTES);
        memset (cert->secret_key, 0, crypto_sign_SECRETKEYBYTES);
        memset (cert->signature, 0, crypto_sign_BYTES);
        cert->magic = ~FLUX_SIGCERT_MAGIC;
        free (cert);
        errno = saved_errno;
    }
}

/* sodium_init() must be called before any other libsodium functions.
 * Checking here should be sufficient since there can be no calls from
 * this module without certs, and all certs are created here.
 */
struct flux_sigcert *sigcert_create (void)
{
    struct flux_sigcert *cert;
    static bool sodium_initialized = false;

    if (!sodium_initialized) {
        if (sodium_init () < 0) {
            errno = EINVAL;
            return NULL;
        }
        sodium_initialized = true;
    }
    if (!(cert = calloc (1, sizeof (*cert))))
        return NULL;
    cert->magic = FLUX_SIGCERT_MAGIC;
    if (!(cert->meta = json_object ())) {
        errno = ENOMEM;
        goto error;
    }
    return cert;
error:
    flux_sigcert_destroy (cert);
    return NULL;
}

struct flux_sigcert *flux_sigcert_create (void)
{
    struct flux_sigcert *cert;

    if (!(cert = sigcert_create ()))
        goto error;
    if (crypto_sign_keypair (cert->public_key, cert->secret_key) < 0)
        goto error;
    cert->secret_valid = true;
    return cert;
error:
    flux_sigcert_destroy (cert);
    return NULL;
}

/* Don't allow '.' in a key or when it's written out to TOML
 * it will look like TOML hierarchy.
 */
int flux_sigcert_meta_sets (struct flux_sigcert *cert,
                            const char *key, const char *s)
{
    json_t *val;

    if (!cert || !key || strchr (key, '.') || !s) {
        errno = EINVAL;
        return -1;
    }
    if (!(val = json_string (s)))
        goto nomem;
    if (json_object_set_new (cert->meta, key, val) < 0)
        goto nomem;
    return 0;
nomem:
    json_decref (val);
    errno = ENOMEM;
    return -1;
}

int flux_sigcert_meta_gets (const struct flux_sigcert *cert,
                            const char *key, const char **sp)
{
    json_t *val;
    const char *s;

    if (!cert || !key || strchr (key, '.') || !sp) {
        errno = EINVAL;
        return -1;
    }
    if (!(val = json_object_get (cert->meta, key))) {
        errno = ENOENT;
        return -1;
    }
    if (!(s = json_string_value (val))) {
        errno = EINVAL;
        return -1;
    }
    *sp = s;
    return 0;
}

int flux_sigcert_meta_seti (struct flux_sigcert *cert,
                            const char *key, int64_t i)
{
    json_t *val;

    if (!cert || !key || strchr (key, '.')) {
        errno = EINVAL;
        return -1;
    }
    if (!(val = json_integer ((json_int_t)i)))
        goto nomem;
    if (json_object_set_new (cert->meta, key, val) < 0)
        goto nomem;
    return 0;
nomem:
    json_decref (val);
    errno = ENOMEM;
    return -1;
}

int flux_sigcert_meta_geti (const struct flux_sigcert *cert,
                            const char *key, int64_t *ip)
{
    json_t *val;

    if (!cert || !key || strchr (key, '.') || !ip) {
        errno = EINVAL;
        return -1;
    }
    if (!(val = json_object_get (cert->meta, key))) {
        errno = ENOENT;
        return -1;
    }
    if (!json_is_integer (val)) {
        errno = EINVAL;
        return -1;
    }
    *ip = json_integer_value (val);
    return 0;
}

int flux_sigcert_meta_setd (struct flux_sigcert *cert,
                            const char *key, double d)
{
    json_t *val;

    if (!cert || !key || strchr (key, '.')) {
        errno = EINVAL;
        return -1;
    }
    if (!(val = json_real (d)))
        goto nomem;
    if (json_object_set_new (cert->meta, key, val) < 0)
        goto nomem;
    return 0;
nomem:
    json_decref (val);
    errno = ENOMEM;
    return -1;
}

int flux_sigcert_meta_getd (const struct flux_sigcert *cert,
                            const char *key, double *dp)
{
    json_t *val;

    if (!cert || !key || strchr (key, '.') || !dp) {
        errno = EINVAL;
        return -1;
    }
    if (!(val = json_object_get (cert->meta, key))) {
        errno = ENOENT;
        return -1;
    }
    if (!json_is_real (val)) {
        errno = EINVAL;
        return -1;
    }
    *dp = json_real_value (val);
    return 0;
}

int flux_sigcert_meta_setb (struct flux_sigcert *cert,
                            const char *key, bool b)
{
    json_t *val;

    if (!cert || !key || strchr (key, '.')) {
        errno = EINVAL;
        return -1;
    }
    val = b ? json_true () : json_false ();
    if (!val)
        goto nomem;
    if (json_object_set_new (cert->meta, key, val) < 0)
        goto nomem;
    return 0;
nomem:
    json_decref (val);
    errno = ENOMEM;
    return -1;
}

int flux_sigcert_meta_getb (const struct flux_sigcert *cert,
                            const char *key, bool *bp)
{
    json_t *val;

    if (!cert || !key || strchr (key, '.') || !bp) {
        errno = EINVAL;
        return -1;
    }
    if (!(val = json_object_get (cert->meta, key))) {
        errno = ENOENT;
        return -1;
    }
    if (!json_is_true (val) && !json_is_false (val)) {
        errno = EINVAL;
        return -1;
    }
    *bp = json_is_true (val) ? true : false;
    return 0;
}

/* Convert time_t (GMT) to ISO 8601 timestamp, e.g. 2003-08-24T05:14:50Z
 */
static int timetostr (time_t t, char *buf, int size)
{
    struct tm tm;
    if (!gmtime_r (&t, &tm))
        return -1;
    if (strftime (buf, size, "%FT%TZ", &tm) == 0)
        return -1;
    return 0;
}

static int strtotime (const char *s, time_t *tp)
{
    struct tm tm;
    time_t t;
    if (!strptime (s, "%FT%TZ", &tm))
        return -1;
    if ((t = timegm (&tm)) < 0)
        return -1;
    *tp = t;
    return 0;
}

/* Timestamp is the only TOML type that doesn't have a corresponding
 * JSON type.  Represent it as a JSON object that looks like this:
 *   { "iso-8601-ts" : "2003-08-24T05:14:50Z" }
 * Since this is the only metadata represented as an object, and
 * metadata is strictly a flat list, this cannot be confused with any
 * of the other metadata types.
 */
int flux_sigcert_meta_setts (struct flux_sigcert *cert,
                             const char *key, time_t t)
{
    json_t *val;
    char timebuf[80];

    if (!cert || !key || strchr (key, '.')) {
        errno = EINVAL;
        return -1;
    }
    if (timetostr (t, timebuf, sizeof (timebuf)) < 0) {
        errno = EINVAL;
        return -1;
    }
    if (!(val = json_pack ("{s:s}", "iso-8601-ts", timebuf)))
        goto nomem;
    if (json_object_set_new (cert->meta, key, val) < 0)
        goto nomem;
    return 0;
nomem:
    json_decref (val);
    errno = ENOMEM;
    return -1;
}

int flux_sigcert_meta_getts (const struct flux_sigcert *cert,
                             const char *key, time_t *tp)
{
    json_t *val;
    const char *s;
    time_t t;

    if (!cert || !key || strchr (key, '.') || !tp) {
        errno = EINVAL;
        return -1;
    }
    if (!(val = json_object_get (cert->meta, key))) {
        errno = ENOENT;
        return -1;
    }
    if (json_unpack (val, "{s:s}", "iso-8601-ts", &s) < 0
                                    || strtotime (s, &t) < 0) {
        errno = EINVAL;
        return -1;
    }
    *tp = t;
    return 0;
}

/* encode public key 'src' to base64 'dst'
 */
static void sigcert_base64_encode_public (const public_t src,
                                          public_base64_t dst)
{
    int srclen = crypto_sign_PUBLICKEYBYTES;
    int dstlen = sizeof (public_base64_t);
    int rc;

    assert (dstlen >= base64_encode_length (srclen));
    rc = base64_encode_block (dst, &dstlen, src, srclen);
    assert (rc == 0);
}
/* decode base64 'src' to public key 'dst'
 * return 0 on success, -1 on failure
 */
static int sigcert_base64_decode_public (const char *src, public_t dst)
{
    int srclen = strlen (src);
    int dstlen = sizeof (public_t);

    if (dstlen < base64_decode_length (srclen))
        goto inval;
    if (base64_decode_block (dst, &dstlen, src, srclen) < 0)
        goto inval;
    if (dstlen != crypto_sign_PUBLICKEYBYTES)
        goto inval;
    return 0;
inval:
    errno = EINVAL;
    return -1;
}

/* encode secret key 'src' to base64 'dst'
 */
static void sigcert_base64_encode_secret (const secret_t src,
                                          secret_base64_t dst)
{
    int srclen = crypto_sign_SECRETKEYBYTES;
    int dstlen = sizeof (secret_base64_t);
    int rc;

    assert (dstlen >= base64_encode_length (srclen));
    rc = base64_encode_block (dst, &dstlen, src, srclen);
    assert (rc == 0);
}
/* decode base64 'src' to secret key 'dst'
 * return 0 on success, -1 on failure
 */
int sigcert_base64_decode_secret (const char *src, secret_t dst)
{
    int srclen = strlen (src);
    int dstlen = sizeof (secret_t);

    if (dstlen < base64_decode_length (srclen))
        goto inval;
    if (base64_decode_block (dst, &dstlen, src, srclen) < 0)
        goto inval;
    if (dstlen != crypto_sign_SECRETKEYBYTES)
        goto inval;
    return 0;
inval:
    errno = EINVAL;
    return -1;
}

/* encode signature 'src' to base64 'dst'
 */
static void sigcert_base64_encode_sign (const sign_t src, sign_base64_t dst)
{
    int srclen = crypto_sign_BYTES;
    int dstlen = sizeof (sign_base64_t);
    int rc;

    assert (dstlen >= base64_encode_length (srclen));
    rc = base64_encode_block (dst, &dstlen, src, srclen);
    assert (rc == 0);
}
/* decode base64 'src' to signature 'dst'
 * return 0 on success, -1 on failure
 */
static int sigcert_base64_decode_sign (const char *src, sign_t dst)
{
    int srclen = strlen (src);
    int dstlen = sizeof (sign_t);

    if (dstlen < base64_decode_length (srclen))
        goto inval;
    if (base64_decode_block (dst, &dstlen, src, srclen) < 0)
        goto inval;
    if (dstlen != crypto_sign_BYTES)
        goto inval;
    return 0;
inval:
    errno = EINVAL;
    return -1;
}

/* fopen(w) with mode parameter
 */
static FILE *fopen_mode (const char *pathname, mode_t mode)
{
    int fd;
    FILE *fp;

    if ((fd = open (pathname, O_WRONLY | O_TRUNC | O_CREAT, mode)) < 0)
        return NULL;
    if (!(fp = fdopen (fd, "w"))) {
        close (fd);
        return NULL;
    }
    return fp;
}

/* Write secret-key (only) to 'fp' in TOML format.
 */
static int sigcert_fwrite_secret (const struct flux_sigcert *cert, FILE *fp)
{
    secret_base64_t seckey;

    // [curve]
    if (fprintf (fp, "[curve]\n") < 0)
        return -1;
    sigcert_base64_encode_secret (cert->secret_key, seckey);
    if (fprintf (fp, "    secret-key = \"%s\"\n", seckey) < 0)
        return -1;
    return 0;
}

/* Write public cert contents (not secret-key) to 'fp' in TOML format.
 */
static int sigcert_fwrite_public (const struct flux_sigcert *cert, FILE *fp)
{
    void *iter;

    // [metadata]
    if (fprintf (fp, "[metadata]\n") < 0)
        goto error;
    iter = json_object_iter (cert->meta);
    while (iter) {
        const char *mkey = json_object_iter_key (iter);
        json_t *val = json_object_iter_value (iter);

        if (!mkey || !val) {
            errno = EINVAL;
            goto error;
        }
        if (json_is_string (val)) {
            if (fprintf (fp, "    %s = \"%s\"\n",
                         mkey, json_string_value (val)) < 0)
                goto error;
        }
        else if (json_is_true (val)) {
            if (fprintf (fp, "    %s = true\n", mkey) < 0)
                goto error;
        }
        else if (json_is_false (val)) {
            if (fprintf (fp, "    %s = false\n", mkey) < 0)
                goto error;
        }
        else if (json_is_integer (val)) {
            if (fprintf (fp, "    %s = %lld\n",
                         mkey, (long long)json_integer_value (val)) < 0)
                goto error;
        }
        else if (json_is_real (val)) {
            if (fprintf (fp, "    %s = %f\n",
                         mkey, json_real_value (val)) < 0)
                goto error;
        }
        else if (json_is_object (val)) {
            const char *s;
            if (json_unpack (val, "{s:s}", "iso-8601-ts", &s) < 0)
                goto error;
            if (fprintf (fp, "    %s = %s\n", mkey, s) < 0)
                goto error;
        }
        else {
            errno = EINVAL;
            goto error;
        }
        iter = json_object_iter_next (cert->meta, iter);
    }
    if (fprintf (fp, "\n") < 0)
        goto error;

    // [curve]
    if (fprintf (fp, "[curve]\n") < 0)
        goto error;

    public_base64_t pubkey;
    sigcert_base64_encode_public (cert->public_key, pubkey);
    if (fprintf (fp, "    public-key = \"%s\"\n", pubkey) < 0)
        goto error;

    if (cert->signature_valid) {
        sign_base64_t sign;
        sigcert_base64_encode_sign (cert->signature, sign);
        if (fprintf (fp, "    signature = \"%s\"\n", sign) < 0)
            goto error;
    }
    return 0;
error:
    return -1;
}

int flux_sigcert_store (const struct flux_sigcert *cert, const char *name)
{
    FILE *fp = NULL;
    char name_pub[PATH_MAX + 1];
    int saved_errno;

    if (!cert || !name || strlen (name) == 0) {
        errno = EINVAL;
        goto error;
    }
    if (snprintf (name_pub, PATH_MAX + 1, "%s.pub", name) >= PATH_MAX + 1)
        goto error;
    if (!(fp = fopen_mode (name_pub, 0644)))
        goto error;
    if (sigcert_fwrite_public (cert, fp) < 0)
        goto error;
    if (fclose (fp) < 0)
        goto error;
    if (cert->secret_valid) {
        if (!(fp = fopen_mode (name, 0600)))
            goto error;
        if (sigcert_fwrite_secret (cert, fp) < 0)
            goto error;
        if (fclose (fp) < 0)
            goto error;
    }
    return 0;
error:
    saved_errno = errno;
    if (fp)
        (void)fclose (fp);
    errno = saved_errno;
    return -1;
}

static int parse_toml_public_key (const char *raw, public_t key)
{
    char *s = NULL;
    int rc = -1;

    if (toml_rtos (raw, &s) < 0)
        goto done;
    if (sigcert_base64_decode_public (s, key) < 0)
        goto done;
    rc = 0;
done:
    free (s);
    return rc;
}

static int parse_toml_secret_key (const char *raw, secret_t key)
{
    char *s = NULL;
    int rc = -1;

    if (toml_rtos (raw, &s) < 0)
        goto done;
    if (sigcert_base64_decode_secret (s, key) < 0)
        goto done;
    rc = 0;
done:
    free (s);
    return rc;
}

static int parse_toml_signature (const char *raw, sign_t sig)
{
    char *s = NULL;
    int rc = -1;

    if (toml_rtos (raw, &s) < 0)
        goto done;
    if (sigcert_base64_decode_sign (s, sig) < 0)
        goto done;
    rc = 0;
done:
    free (s);
    return rc;
}

static int parse_toml_meta_set (const char *raw, struct flux_sigcert *cert,
                                const char *key)
{
    char *s = NULL;
    int rc = -1;
    int64_t i;
    double d;
    int b;
    toml_timestamp_t ts;

    if (toml_rtos (raw, &s) == 0) {
        if (flux_sigcert_meta_sets (cert, key, s) < 0)
            goto done;
    }
    else if (toml_rtob (raw, &b) == 0) {
        if (flux_sigcert_meta_setb (cert, key, b) < 0)
            goto done;
    }
    else if (toml_rtoi (raw, &i) == 0) {
        if (flux_sigcert_meta_seti (cert, key, i) < 0)
            goto done;
    }
    else if (toml_rtod (raw, &d) == 0) {
        if (flux_sigcert_meta_setd (cert, key, d) < 0)
            goto done;
    }
    else if (toml_rtots (raw, &ts) == 0) {
        struct tm tm;
        time_t t;
        if (!ts.year || !ts.month || !ts.day)
            goto done;
        if (!ts.hour || !ts.minute || !ts.second)
            goto done;
        memset (&tm, 0, sizeof (tm));
        tm.tm_year = *ts.year - 1900;
        tm.tm_mon = *ts.month - 1;
        tm.tm_mday = *ts.day;
        tm.tm_hour = *ts.hour;
        tm.tm_min = *ts.minute;
        tm.tm_sec = *ts.second;
        if ((t = timegm (&tm)) < 0)
            goto done;
        if (flux_sigcert_meta_setts (cert, key, t) < 0)
            goto done;
    }
    else
        goto done;
    rc = 0;
done:
    free (s);
    return rc;
}

/* Read in secret-key.
 */
static int sigcert_fread_secret (struct flux_sigcert *cert, FILE *fp)
{
    toml_table_t *cert_table = NULL;
    toml_table_t *curve_table;
    const char *raw;
    char errbuf[200];

    if (!(cert_table = toml_parse_file (fp, errbuf, sizeof (errbuf))))
        goto inval;
    if (!(curve_table = toml_table_in (cert_table, "curve")))
        goto inval;
    if (!(raw = toml_raw_in (curve_table, "secret-key")))
        goto inval;
    if (parse_toml_secret_key (raw, cert->secret_key) < 0)
        goto inval;
    cert->secret_valid = true;
    toml_free (cert_table);
    return 0;
inval:
    toml_free (cert_table);
    errno = EINVAL;
    return -1;
}

/* Read public cert contents from 'fp' in TOML format.
 */
static int sigcert_fread_public (struct flux_sigcert *cert, FILE *fp)
{
    toml_table_t *cert_table = NULL;
    toml_table_t *curve_table;
    toml_table_t *meta_table;
    const char *key;
    const char *raw;
    int i;
    char errbuf[200];

    if (!(cert_table = toml_parse_file (fp, errbuf, sizeof (errbuf))))
        goto inval;

    // [metadata]
    if (!(meta_table = toml_table_in (cert_table, "metadata")))
        goto inval;
    for (i = 0; (key = toml_key_in (meta_table, i)); i++) {
        if (!(raw = toml_raw_in (meta_table, key)))
            goto inval;
        if (parse_toml_meta_set (raw, cert, key) < 0)
            goto inval;
    }

    // [curve]
    if (!(curve_table = toml_table_in (cert_table, "curve")))
        goto inval;
    if (!(raw = toml_raw_in (curve_table, "public-key")))
        goto inval;
    if (parse_toml_public_key (raw, cert->public_key) < 0)
        goto inval;
    if ((raw = toml_raw_in (curve_table, "signature"))) { // optional
        if (parse_toml_signature (raw, cert->signature) < 0)
            goto inval;
        cert->signature_valid = true;
    }
    toml_free (cert_table);
    return 0;
inval:
    toml_free (cert_table);
    errno = EINVAL;
    return -1;
}

struct flux_sigcert *flux_sigcert_load (const char *name, bool secret)
{
    FILE *fp = NULL;
    char name_pub[PATH_MAX + 1];
    int saved_errno;
    struct flux_sigcert *cert = NULL;

    if (!name)
        goto inval;
    if (snprintf (name_pub, PATH_MAX + 1, "%s.pub", name) >= PATH_MAX + 1)
        goto inval;
    if (!(cert = sigcert_create ()))
        return NULL;
    // name.pub - public
    if (!(fp = fopen (name_pub, "r")))
        goto error;
    if (sigcert_fread_public (cert, fp) < 0)
        goto error;
    if (fclose (fp) < 0)
        goto error;
    // name - secret
    if (secret) {
        if (!(fp = fopen (name, "r")))
            goto error;
        if (sigcert_fread_secret (cert, fp) < 0)
            goto error;
        if (fclose (fp) < 0)
            goto error;
    }
    return cert;
inval:
    errno = EINVAL;
error:
    saved_errno = errno;
    if (fp)
        (void)fclose (fp);
    flux_sigcert_destroy (cert);
    errno = saved_errno;
    return NULL;
}

/* Encode 'sign' as base64 and add signature = sign_base64 to 'obj'.
 */
static int sigcert_pack_signature (const sign_t sign, json_t *obj)
{
    sign_base64_t sign_base64;
    json_t *sigobj;

    if (!obj) {
        errno = EINVAL;
        return -1;
    }
    sigcert_base64_encode_sign (sign, sign_base64);
    sigobj = json_string (sign_base64);
    if (!sigobj || json_object_set_new (obj, "signature", sigobj) < 0) {
        json_decref (sigobj);
        errno = ENOMEM;
        return -1;
    }
    return 0;
}

/* This is used to serialize the cert for signing.
 * The secret key is always exluded.
 * The signature is included if signature=true and it's valid.
 * IMPORTANT:  This serialization is used for generating a signature over
 * the cert itself.  It's not exposed outside of this module for that purpose,
 * but changing it could make certs that were signed before the change fail
 * verification!
 */
static char *sigcert_json_dumps (const struct flux_sigcert *cert,
                                 bool signature)
{
    json_t *obj = NULL;
    public_base64_t pubkey;
    int saved_errno;
    char *s;

    if (!cert) {
        errno = EINVAL;
        return NULL;
    }
    sigcert_base64_encode_public (cert->public_key, pubkey);
    if (!(obj = json_pack ("{s:O,s:{s:s}}",
                           "metadata", cert->meta,
                           "curve",
                             "public-key", pubkey))) {
        errno = ENOMEM;
        goto error;
    }
    if (signature && cert->signature_valid) {
        if (sigcert_pack_signature (cert->signature,
                                    json_object_get (obj, "curve")) < 0)
            goto error;
    }
    if (!(s = json_dumps (obj, JSON_COMPACT|JSON_SORT_KEYS))) {
        errno = ENOMEM;
        goto error;
    }
    json_decref (obj);
    return s;
error:
    saved_errno = errno;
    json_decref (obj);
    errno = saved_errno;
    return NULL;
}

char *flux_sigcert_json_dumps (const struct flux_sigcert *cert)
{
    return sigcert_json_dumps (cert, true);
}

struct flux_sigcert *flux_sigcert_json_loads (const char *s)
{
    json_t *obj = NULL;
    json_t *curve, *sig;
    struct flux_sigcert *cert = NULL;
    const char *pub;
    int saved_errno;

    if (!s) {
        errno = EINVAL;
        return NULL;
    }
    if (!(cert = sigcert_create ()))
        return NULL;
    json_decref (cert->meta); // we create cert->meta from scratch below
    cert->meta = NULL;

    if (!(obj = json_loads (s, 0, NULL))) {
        errno = EPROTO;
        goto error;
    }
    if (json_unpack (obj, "{s:O,s:{s:s}}",
                     "metadata", &cert->meta,
                     "curve",
                       "public-key", &pub) < 0) {
        errno = EPROTO;
        goto error;
    }
    if (sigcert_base64_decode_public (pub, cert->public_key) < 0) {
        errno = EPROTO;
        goto error;
    }
    if (!(curve = json_object_get (obj, "curve"))) {
        errno = EINVAL;
        goto error;
    }
    if ((sig = json_object_get (curve, "signature"))) {
        if (sigcert_base64_decode_sign (json_string_value (sig),
                                        cert->signature) < 0) {
            errno = EPROTO;
            goto error;
        }
        cert->signature_valid = true;
    }
    json_decref (obj);
    return cert;
error:
    saved_errno = errno;
    json_decref (obj);
    flux_sigcert_destroy (cert);
    errno = saved_errno;
    return NULL;
}

bool flux_sigcert_equal (const struct flux_sigcert *cert1,
                         const struct flux_sigcert *cert2)
{
    if (!cert1 || !cert2)
        return false;
    if (!json_equal (cert1->meta, cert2->meta))
        return false;
    if (memcmp (cert1->public_key, cert2->public_key,
                                   crypto_sign_PUBLICKEYBYTES) != 0)
        return false;
    if (cert1->secret_valid != cert2->secret_valid)
        return false;
    if (cert1->secret_valid) {
        if (memcmp (cert1->secret_key, cert2->secret_key,
                                       crypto_sign_SECRETKEYBYTES) != 0)
            return false;
    }
    return true;
}

char *flux_sigcert_sign (const struct flux_sigcert *cert,
                         uint8_t *buf, int len)
{
    sign_t sig;
    sign_base64_t sig_base64;

    if (!cert || !cert->secret_valid || len < 0 || (len > 0 && buf == NULL)) {
        errno = EINVAL;
        return NULL;
    }
    if (crypto_sign_detached (sig, NULL, buf, len, cert->secret_key) < 0) {
        errno = EINVAL;
        return NULL;
    }
    sigcert_base64_encode_sign (sig, sig_base64);
    return strdup (sig_base64);
}

int flux_sigcert_verify (const struct flux_sigcert *cert,
                         const char *sig_base64, uint8_t *buf, int len)
{
    sign_t sig;

    if (!cert || !sig_base64 || len < 0 || (len > 0 && buf == NULL)) {
        errno = EINVAL;
        return -1;
    }
    if (sigcert_base64_decode_sign (sig_base64, sig) < 0)
        return -1;
    if (crypto_sign_verify_detached (sig, buf, len, cert->public_key) < 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

/* cert1 signs cert2.
 * Dump cert2 as JSON in a repeatable way, excluding secret + signature,
 * sign with cert1.  Add 'signature' attribute to [curve] stanza.
 */
int flux_sigcert_sign_cert (const struct flux_sigcert *cert1,
                            struct flux_sigcert *cert2)
{
    char *s;
    int rc;

    if (!cert1 || !cert2 || !cert1->secret_valid) {
        errno = EINVAL;
        return -1;
    }
    if (!(s = sigcert_json_dumps (cert2, false)))
        return -1;
    rc = crypto_sign_detached (cert2->signature, NULL,
                               (uint8_t *)s, strlen (s),
                               cert1->secret_key);
    free (s);
    if (rc < 0) {
        errno = EINVAL;
        return -1;
    }
    cert2->signature_valid = true;
    return 0;
}

int flux_sigcert_verify_cert (const struct flux_sigcert *cert1,
                              const struct flux_sigcert *cert2)
{
    char *s;
    int rc;

    if (!cert1 || !cert2 || !cert2->signature_valid) {
        errno = EINVAL;
        return -1;
    }
    if (!(s = sigcert_json_dumps (cert2, false)))
        return -1;
    rc = crypto_sign_verify_detached (cert2->signature,
                                      (uint8_t *)s, strlen (s),
                                      cert1->public_key);
    free (s);
    if (rc < 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
