/* xsign_curve.c - create invalid signatures for curve mechanism
 *
 * Usage: xsign_curve cert testname <input >output
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
#include <assert.h>
#include <sodium.h>

#include "src/libutil/kv.h"
#include "src/libca/sigcert.h"

enum {
    HASH_TYPE_INVALID = 0,
    HASH_TYPE_SHA256 = 1,
    HASH_TYPE_BOGUS = 42,
};

const char *prog = "xsign_curve";

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

static int header_put_cert (struct kv *header, const char *prefix,
                            const struct sigcert *cert)
{
    const char *buf;
    int bufsz;
    struct kv *kv = NULL;

    if (sigcert_encode (cert, &buf, &bufsz) < 0)
        return -1;
    if (!(kv = kv_decode (buf, bufsz)))
        return -1;
    if (kv_join (header, kv, prefix) < 0)
        goto error;
    kv_destroy (kv);
    return 0;
error:
    kv_destroy (kv);
    return -1;
}

static char *make_header (int64_t userid, time_t ctime, time_t xtime,
                          const struct sigcert *cert, bool bad_header,
                          bool no_header)
{
    struct kv *header;
    const char *src;
    int srclen;
    char *dst;
    int dstlen;

    if (!(header = kv_create ()))
        die ("kv_create: %s", strerror (errno));
    if (!no_header) {
        if (kv_put (header, "version", KV_INT64, 1LL) < 0
            || kv_put (header, "mechanism", KV_STRING, "curve") < 0
            || kv_put (header, "userid", KV_INT64, userid) < 0
            || kv_put (header, "curve.ctime", KV_TIMESTAMP, ctime) < 0
            || kv_put (header, "curve.xtime", KV_TIMESTAMP, xtime) < 0
            || header_put_cert (header, "curve.cert.", cert) < 0)
            die ("kv_put: %s", strerror (errno));
        if (bad_header) {
            if (kv_delete (header, "curve.xtime") < 0)
                die ("kv_delete: %s", strerror (errno));
        }
    }
    if (kv_encode (header, &src, &srclen) < 0)
        die ("kv_encode: %s", strerror (errno));
    dstlen = sodium_base64_encoded_len (srclen,
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

    dstlen = sodium_base64_encoded_len (srclen,
                                        sodium_base64_VARIANT_ORIGINAL);
    if (!(dst = malloc (dstlen)))
        die ("malloc: %s", strerror (errno));
    sodium_bin2base64 (dst, dstlen, src, srclen,
                       sodium_base64_VARIANT_ORIGINAL);
    return dst;
}


static char *test_sign_wrap (const void *pay, int paysz,
                             const struct sigcert *cert,
                             int64_t userid, time_t ctime, time_t xtime,
                             bool change_payload, bool bad_header,
                             bool no_header)
{
    char *header;
    char *payload;
    char *signature;
    char *headerpayload;
    char *msg;

    header = make_header (userid, ctime, xtime, cert, bad_header, no_header);
    payload = make_payload (pay, paysz);

    if (asprintf (&headerpayload, "%s.%s", header, payload) < 0)
        die ("asprintf: %s", strerror (errno));

    if (!(signature = sigcert_sign_detached (cert, (uint8_t *)headerpayload,
                                                   strlen (headerpayload))))
        die ("sigcert_sign_detached: %s", strerror (errno));

    if (change_payload) {
        free (payload);
        payload = make_payload ("bogus", 5);
    }
    if (asprintf (&msg, "%s.%s.%s", header, payload, signature) < 0)
        die ("asprintf: %s", strerror (errno));

    free (header);
    free (payload);
    free (headerpayload);
    free (signature);

    return msg;
}

int main (int argc, char **argv)
{
    char buf[1024];
    int buflen;
    char *msg = NULL;
    struct sigcert *cert;
    time_t now;

    if (argc != 3)
        die ("Usage: %s cert {good|xuser|xpaychg|xctime|xxtime|xheader|xnoheader} <input >output", prog);

    if ((now = time (NULL)) == (time_t)-1)
        die ("time: %s", strerror (errno));
    if (!(cert = sigcert_load (argv[1], true)))
        die ("sigcert_load %s: %s", argv[1], strerror (errno));
    buflen = read_all (buf, sizeof (buf));

    if (!strcmp (argv[2], "good"))
        msg = test_sign_wrap (buf, buflen, cert, getuid (),
                              now, now + 1, false, false, false);
    else if (!strcmp (argv[2], "xuser"))
        msg = test_sign_wrap (buf, buflen, cert, getuid () + 1,
                              now, now + 1, false, false, false);
    else if (!strcmp (argv[2], "xpaychg"))
        msg = test_sign_wrap (buf, buflen, cert, getuid (),
                              now, now + 1, true, false, false);
    else if (!strcmp (argv[2], "xctime"))
        msg = test_sign_wrap (buf, buflen, cert, getuid (),
                              now + 2, now + 3, false, false, false);
    else if (!strcmp (argv[2], "xxtime"))
        msg = test_sign_wrap (buf, buflen, cert, getuid (),
                              now, now - 1, false, false, false);
    else if (!strcmp (argv[2], "xheader"))
        msg = test_sign_wrap (buf, buflen, cert, getuid (),
                              now, now + 1, false, true, false);
    else if (!strcmp (argv[2], "xnoheader"))
        msg = test_sign_wrap (buf, buflen, cert, getuid (),
                              now, now + 1, false, false, true);
    else
        die ("unknown test: %s", argv[1]);

    assert (msg != NULL);
    printf ("%s\n", msg);
    free (msg);
    sigcert_destroy (cert);

    return 0;
}

/* vi: ts=4 sw=4 expandtab
 */
