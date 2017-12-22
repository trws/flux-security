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
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <sodium.h>

#include "base64.h"
#include "tomltk.h"
#include "kv.h"

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
struct sigcert {
    int magic;

    public_t public_key;
    secret_t secret_key;
    sign_t signature;

    struct kv *meta;

    bool secret_valid;
    bool signature_valid;

    struct kv *enc;
};

void sigcert_destroy (struct sigcert *cert)
{
    if (cert) {
        int saved_errno = errno;
        assert (cert->magic == FLUX_SIGCERT_MAGIC);
        kv_destroy (cert->enc);
        kv_destroy (cert->meta);
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
static struct sigcert *sigcert_alloc (void)
{
    struct sigcert *cert;
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
    if (!(cert->meta = kv_create ())) {
        errno = ENOMEM;
        goto error;
    }
    return cert;
error:
    sigcert_destroy (cert);
    return NULL;
}

struct sigcert *sigcert_create (void)
{
    struct sigcert *cert;

    if (!(cert = sigcert_alloc ()))
        goto error;
    if (crypto_sign_keypair (cert->public_key, cert->secret_key) < 0)
        goto error;
    cert->secret_valid = true;
    return cert;
error:
    sigcert_destroy (cert);
    return NULL;
}

struct sigcert *sigcert_copy (const struct sigcert *cert)
{
    struct sigcert *cpy;
    struct kv *metacpy;

    if (!cert) {
        errno = EINVAL;
        return NULL;
    }
    if (!(metacpy = kv_copy (cert->meta)))
        return NULL;
    if (!(cpy = malloc (sizeof (*cpy)))) {
        kv_destroy (metacpy);
        return NULL;
    }
    memcpy (cpy, cert, sizeof (*cpy));
    cpy->meta = metacpy;
    return cpy;
}

void sigcert_forget_secret (struct sigcert *cert)
{
    if (cert && cert->secret_valid) {
        memset (cert->secret_key, 0, crypto_sign_SECRETKEYBYTES);
        cert->secret_valid = false;
    }
}

static enum kv_type type_tokv (enum sigcert_meta_type type)
{
    switch (type) {
        case SM_STRING:
            return KV_STRING;
        case SM_INT64:
            return KV_INT64;
        case SM_DOUBLE:
            return KV_DOUBLE;
        case SM_BOOL:
            return KV_BOOL;
        case SM_TIMESTAMP:
            return KV_TIMESTAMP;
        default:
            return KV_UNKNOWN;
    }
}

/* Don't allow '.' in a key or when it's written out to TOML
 * it will look like TOML hierarchy.
 */
static int sigcert_meta_vset (struct sigcert *cert, const char *key,
                              enum sigcert_meta_type type, va_list ap)
{
    if (!cert || !key || strchr (key, '.')) {
        errno = EINVAL;
        return -1;
    }
    return kv_vput (cert->meta, key, type_tokv (type), ap);
}

int sigcert_meta_set (struct sigcert *cert, const char *key,
                      enum sigcert_meta_type type, ...)
{
    int rc;
    va_list ap;

    va_start (ap, type);
    rc = sigcert_meta_vset (cert, key, type, ap);
    va_end (ap);

    return rc;
}

static int sigcert_meta_vget (const struct sigcert *cert, const char *key,
                              enum sigcert_meta_type type, va_list ap)
{
    if (!cert || !key || strchr (key, '.')) {
        errno = EINVAL;
        return -1;
    }
    return kv_vget (cert->meta, key, type_tokv (type), ap);
}

int sigcert_meta_get (const struct sigcert *cert, const char *key,
                      enum sigcert_meta_type type, ...)
{
    int rc;
    va_list ap;

    va_start (ap, type);
    rc = sigcert_meta_vget (cert, key, type, ap);
    va_end (ap);

    return rc;
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
static int sigcert_fwrite_secret (const struct sigcert *cert, FILE *fp)
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
static int sigcert_fwrite_public (const struct sigcert *cert, FILE *fp)
{
    const char *key = NULL;

    // [metadata]
    if (fprintf (fp, "[metadata]\n") < 0)
        goto error;
    while ((key = kv_next (cert->meta, key))) {
        switch (kv_typeof (key)) {
            case KV_STRING:
                if (fprintf (fp, "    %s = \"%s\"\n",
                             key, kv_val_string (key)) < 0)
                    goto error;
                break;
            case KV_INT64:
                if (fprintf (fp, "    %s = %" PRIi64 "\n",
                             key, kv_val_int64 (key)) < 0)
                    goto error;
                break;
            case KV_DOUBLE:
                if (fprintf (fp, "    %s = %f\n",
                             key, kv_val_double (key)) < 0)
                    goto error;
                break;
            case KV_BOOL:       // kv_val_string is "true" or "false"
            case KV_TIMESTAMP:  // kv_val_string is ISO 8601 time string
                if (fprintf (fp, "    %s = %s\n",
                             key, kv_val_string (key)) < 0)
                    goto error;
                break;
            default:
                errno = EINVAL;
                goto error;
        }
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

int sigcert_store (const struct sigcert *cert, const char *name)
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

static int parse_toml_meta_set (const char *raw, struct sigcert *cert,
                                const char *key)
{
    char *s = NULL;
    int rc = -1;
    int64_t i;
    double d;
    int b;
    toml_timestamp_t ts;

    if (toml_rtos (raw, &s) == 0) {
        if (sigcert_meta_set (cert, key, SM_STRING, s) < 0)
            goto done;
    }
    else if (toml_rtob (raw, &b) == 0) {
        if (sigcert_meta_set (cert, key, SM_BOOL, b) < 0)
            goto done;
    }
    else if (toml_rtoi (raw, &i) == 0) {
        if (sigcert_meta_set (cert, key, SM_INT64, i) < 0)
            goto done;
    }
    else if (toml_rtod (raw, &d) == 0) {
        if (sigcert_meta_set (cert, key, SM_DOUBLE, d) < 0)
            goto done;
    }
    else if (toml_rtots (raw, &ts) == 0) {
        time_t t;
        if (tomltk_ts_to_epoch (&ts, &t) < 0)
            goto done;
        if (sigcert_meta_set (cert, key, SM_TIMESTAMP, t) < 0)
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
static int sigcert_fread_secret (struct sigcert *cert, FILE *fp)
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
static int sigcert_fread_public (struct sigcert *cert, FILE *fp)
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

struct sigcert *sigcert_load (const char *name, bool secret)
{
    FILE *fp = NULL;
    char name_pub[PATH_MAX + 1];
    int saved_errno;
    struct sigcert *cert = NULL;

    if (!name)
        goto inval;
    if (snprintf (name_pub, PATH_MAX + 1, "%s.pub", name) >= PATH_MAX + 1)
        goto inval;
    if (!(cert = sigcert_alloc ()))
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
    sigcert_destroy (cert);
    errno = saved_errno;
    return NULL;
}

static int get_pubkey (struct kv *kv, uint8_t *pub)
{
    const char *pub_s;
    if (kv_get (kv, "curve.public-key", KV_STRING, &pub_s) < 0)
        return -1;
    return sigcert_base64_decode_public (pub_s, pub);
}

static int get_signature (struct kv *kv, uint8_t *sign)
{
    const char *sign_s;

    if (kv_get (kv, "curve.signature", KV_STRING, &sign_s) < 0)
        return -1;
    return sigcert_base64_decode_sign (sign_s, sign);
}

struct sigcert *sigcert_decode (const char *s, int len)
{
    struct kv *kv;
    struct sigcert *cert;

    if (!s || len == 0) {
        errno = EINVAL;
        return NULL;
    }
    if (!(kv = kv_decode (s, len)))
        return NULL;
    if (!(cert = sigcert_alloc ()))
        goto error;

    kv_destroy (cert->meta);
    if (!(cert->meta = kv_split (kv, "meta.")))
        goto error;
    if (get_pubkey (kv, cert->public_key) < 0)
        goto error;
    if (get_signature (kv, cert->signature) == 0)
        cert->signature_valid = true;
    else if (errno != ENOENT)
        goto error;
    kv_destroy (kv);
    return cert;
error:
    kv_destroy (kv);
    sigcert_destroy (cert);
    return NULL;
}

static int put_pubkey (struct kv *kv, const uint8_t *pub)
{
    public_base64_t pub_s;

    sigcert_base64_encode_public (pub, pub_s);
    return kv_put (kv, "curve.public-key", KV_STRING, pub_s);
}

static int put_signature (struct kv *kv, const uint8_t *sign)
{
    sign_base64_t sign_s;

    sigcert_base64_encode_sign (sign, sign_s);
    return kv_put (kv, "curve.signature", KV_STRING, sign_s);
}

int sigcert_encode (const struct sigcert *cert, const char **buf, int *len)
{
    if (!cert || !buf || !len) {
        errno = EINVAL;
        return -1;
    }
    kv_destroy (cert->enc);
    if (!(((struct sigcert *)(cert))->enc = kv_create()))
        return -1;
    if (kv_join (cert->enc, cert->meta, "meta.") < 0)
        return -1;
    if (put_pubkey (cert->enc, cert->public_key) < 0)
        return -1;
    if (cert->signature_valid) {
        if (put_signature (cert->enc, cert->signature) < 0)
            return -1;
    }
    return kv_encode (cert->enc, buf, len);
}

bool sigcert_equal (const struct sigcert *cert1,
                    const struct sigcert *cert2)
{
    if (!cert1 || !cert2)
        return false;
    if (!kv_equal (cert1->meta, cert2->meta))
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

char *sigcert_sign_detached (const struct sigcert *cert,
                             const uint8_t *buf, int len)
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

int sigcert_verify_detached (const struct sigcert *cert,
                             const char *signature,
                             const uint8_t *buf, int len)
{
    sign_t sig;

    if (!cert || !signature || len < 0 || (len > 0 && buf == NULL)) {
        errno = EINVAL;
        return -1;
    }
    if (sigcert_base64_decode_sign (signature, sig) < 0)
        return -1;
    if (crypto_sign_verify_detached (sig, buf, len, cert->public_key) < 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int sigcert_sign_length (const char *s)
{
    return sizeof (sign_base64_t) + 1 + (s ? strlen (s) : 0);
}

int sigcert_sign (const struct sigcert *cert, char *buf, int buflen)
{
    sign_t sig;
    int len;

    if (!cert || !cert->secret_valid || buflen < sigcert_sign_length (buf)) {
        errno = EINVAL;
        return -1;
    }
    len = buf ? strlen (buf) : 0;
    if (crypto_sign_detached (sig, NULL, (unsigned char *)buf,
                              len, cert->secret_key) < 0) {
        errno = EINVAL;
        return -1;
    }
    buf[len] = '.';
    sigcert_base64_encode_sign (sig, &buf[len + 1]);
    return 0;
}

int sigcert_verify (const struct sigcert *cert, const char *s)
{
    char *sig;
    int length;

    if (!(sig = strrchr (s, '.'))) {
        errno = EINVAL;
        return -1;
    }
    length = sig - s;
    sig++;
    if (sigcert_verify_detached (cert, sig, (uint8_t *)s, length) < 0)
        return -1;
    return length;
}

/* cert1 signs cert2.
 * Dump cert2 as JSON in a repeatable way, excluding secret + signature,
 * sign with cert1.  Add 'signature' attribute to [curve] stanza.
 */
int sigcert_sign_cert (const struct sigcert *cert1,
                       struct sigcert *cert2)
{
    struct kv *kv;
    const char *kv_s;
    int kv_len;
    int rc = -1;

    if (!cert1 || !cert2 || !cert1->secret_valid) {
        errno = EINVAL;
        return -1;
    }
    if (!(kv = kv_create()))
        return -1;
    if (put_pubkey (kv, cert2->public_key) < 0)
        goto done;
    if (kv_join (kv, cert2->meta, "meta.") < 0)
        goto done;
    if (kv_encode (kv, &kv_s, &kv_len) < 0)
        goto done;
    if (crypto_sign_detached (cert2->signature, NULL,
                              (uint8_t *)kv_s, kv_len,
                              cert1->secret_key) < 0) {
        errno = EINVAL;
        goto done;
    }
    cert2->signature_valid = true;
    rc = 0;
done:
    kv_destroy (kv);
    return rc;
}

int sigcert_verify_cert (const struct sigcert *cert1,
                         const struct sigcert *cert2)
{
    struct kv *kv;
    const char *kv_s;
    int kv_len;
    int rc = -1;

    if (!cert1 || !cert2 || !cert2->signature_valid) {
        errno = EINVAL;
        return -1;
    }
    if (!(kv = kv_create()))
        return -1;
    if (put_pubkey (kv, cert2->public_key) < 0)
        goto done;
    if (kv_join (kv, cert2->meta, "meta.") < 0)
        goto done;
    if (kv_encode (kv, &kv_s, &kv_len) < 0)
        goto done;
    if (crypto_sign_verify_detached (cert2->signature,
                                     (uint8_t *)kv_s, kv_len,
                                     cert1->public_key) < 0) {
        errno = EINVAL;
        goto done;
    }
    rc = 0;
done:
    kv_destroy (kv);
    return rc;
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
