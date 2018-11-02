/* xsign_munge.c - create invalid signatures for munge mechanism
 *
 * Usage: xsign_munge testname <input >output
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <munge.h>
#include <assert.h>
#include <sodium.h>

#include "src/libutil/kv.h"
#include "src/libutil/sha256.h"

enum {
    HASH_TYPE_INVALID = 0,
    HASH_TYPE_SHA256 = 1,
    HASH_TYPE_BOGUS = 42,
};

const char *prog = "xsign_munge";

static void die (const char *fmt, ...)
{
    va_list ap;
    char buf[256];

    va_start (ap, fmt);
    (void)vsnprintf (buf, sizeof (buf), fmt, ap);
    va_end (ap);
    fprintf (stderr, "%s: %s\n", prog, buf);
    exit (1);
}

static int read_all (void *buf, int bufsz)
{
    int n;
    int count = 0;
    do {
        if ((n = read (STDIN_FILENO, (char *)buf + count, bufsz - count)) < 0)
            die ("read stdin: %s", strerror (errno));
        count += n;
    } while (n > 0 && count < bufsz);
    if (n > 0)
        die ("input buffer exceeded");
    return count;
}

static char *make_header (int64_t userid)
{
    struct kv *header;
    const char *src;
    int srclen;
    char *dst;
    int dstlen;

    if (!(header = kv_create ()))
        die ("kv_create: %s", strerror (errno));
    if (kv_put (header, "version", KV_INT64, 1LL) < 0
        || kv_put (header, "mechanism", KV_STRING, "munge") < 0
        || kv_put (header, "userid", KV_INT64, userid) < 0)
        die ("kv_put: %s", strerror (errno));
    if (kv_encode (header, &src, &srclen) < 0)
        die ("kv_encode: %s", strerror (errno));
    dstlen = sodium_base64_ENCODED_LEN (srclen,
                                        sodium_base64_VARIANT_ORIGINAL);
    if (!(dst = malloc (dstlen)))
        die ("malloc: %s", strerror (errno));
    sodium_bin2base64 (dst, dstlen, (const unsigned char *)src, srclen,
                       sodium_base64_VARIANT_ORIGINAL);

    kv_destroy (header);

    return dst;
}

static char *make_payload (const void *src, int srclen)
{
    char *dst;
    int dstlen;

    dstlen = sodium_base64_ENCODED_LEN (srclen,
                                        sodium_base64_VARIANT_ORIGINAL);
    if (!(dst = malloc (dstlen)))
        die ("malloc: %s", strerror (errno));
    sodium_bin2base64 (dst, dstlen, src, srclen,
                       sodium_base64_VARIANT_ORIGINAL);
    return dst;
}

static char *make_signature (munge_ctx_t munge, const char *headerpayload,
                             uint8_t hashtype, int truncate_hash,
                             bool change_hash)
{
    BYTE digest[SHA256_BLOCK_SIZE + 1];
    SHA256_CTX shx;
    char *cred = NULL;
    munge_err_t e;

    digest[0] = hashtype;
    sha256_init (&shx);
    sha256_update (&shx, (const BYTE *)headerpayload,
                   strlen (headerpayload) - truncate_hash);
    sha256_final (&shx, digest + 1);
    if (change_hash)
        digest[1]++;
    e = munge_encode (&cred, munge, digest, sizeof (digest));
    if (e != EMUNGE_SUCCESS)
        die ("munge_encode: %s", munge_ctx_strerror (munge));
    return cred;
}

static char *test_sign_wrap (const void *pay, int paysz, int64_t userid,
                             uint8_t hashtype, int truncate_hash,
                             bool change_hash, bool change_payload,
                             bool change_cred)
{
    const char *socket = getenv ("MUNGE_SOCKET");
    munge_ctx_t munge;
    char *header;
    char *payload;
    char *signature;
    char *headerpayload;
    char *msg;

    if (!(munge = munge_ctx_create ()))
        die ("munge_ctx_create: %s", strerror (errno));
    if (socket) {
        if (munge_ctx_set (munge, MUNGE_OPT_SOCKET, socket) != EMUNGE_SUCCESS)
            die ("munge_ctx_set OPT_SOCKET: %s", munge_ctx_strerror (munge));
    }

    header = make_header (userid);
    payload = make_payload (pay, paysz);

    if (asprintf (&headerpayload, "%s.%s", header, payload) < 0)
        die ("asprintf: %s", strerror (errno));

    signature = make_signature (munge, headerpayload, hashtype, truncate_hash,
                                change_hash);

    if (change_payload) {
        free (payload);
        payload = make_payload ("bogus", 5);
    }
    if (change_cred) {
        signature[10]++;
    }

    if (asprintf (&msg, "%s.%s.%s", header, payload, signature) < 0)
        die ("asprintf: %s", strerror (errno));

    free (header);
    free (payload);
    free (headerpayload);
    free (signature);
    munge_ctx_destroy (munge);

    return msg;
}

int main (int argc, char **argv)
{
    char buf[1024];
    int buflen;
    char *msg = NULL;

    if (argc != 2)
        die ("Usage: xsign_munge {good|xuser|xhashtype|xhashtrun|xhashchg|xpaychg|xcredchg} <input >output");

    buflen = read_all (buf, sizeof (buf));

    if (!strcmp (argv[1], "good"))
        msg = test_sign_wrap (buf, buflen, getuid (), HASH_TYPE_SHA256,
                              0, false, false, false);
    else if (!strcmp (argv[1], "xuser"))
        msg = test_sign_wrap (buf, buflen, getuid () + 1, HASH_TYPE_SHA256,
                              0, false, false, false);
    else if (!strcmp (argv[1], "xhashtype"))
        msg = test_sign_wrap (buf, buflen, getuid (), HASH_TYPE_BOGUS,
                              0, false, false, false);
    else if (!strcmp (argv[1], "xhashtrunc"))
        msg = test_sign_wrap (buf, buflen, getuid (), HASH_TYPE_SHA256,
                              1, false, false, false);
    else if (!strcmp (argv[1], "xhashchg"))
        msg = test_sign_wrap (buf, buflen, getuid (), HASH_TYPE_SHA256,
                              0, true, false, false);
    else if (!strcmp (argv[1], "xpaychg"))
        msg = test_sign_wrap (buf, buflen, getuid (), HASH_TYPE_SHA256,
                              0, false, true, false);
    else if (!strcmp (argv[1], "xcredchg"))
        msg = test_sign_wrap (buf, buflen, getuid (), HASH_TYPE_SHA256,
                              0, false, false, true);
    else
        die ("unknown test: %s", argv[1]);

    assert (msg != NULL);
    printf ("%s\n", msg);
    free (msg);

    return 0;
}

/* vi: ts=4 sw=4 expandtab
 */
