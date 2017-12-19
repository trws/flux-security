#if HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "src/libtap/tap.h"
#include "kv.h"

static void diag_kv (struct kv *kv)
{
    const char *buf;
    int len;
    int i;

    if (kv_raw_encode (kv, &buf, &len) < 0)
        BAIL_OUT ("diag_kv: %s", strerror (errno));
    printf ("# ");
    for (i = 0; i < len; i++) {
        if (buf[i] == '\0')
            printf ("\\0");
        else
            putchar (buf[i]);
    }
    putchar ('\n');
}

static void simple_test (void)
{
    struct kv *kv;
    struct kv *kv2;
    struct kv *kv3;
    const char *s;
    const char *key;
    int len;

    /* Create kv object and set a=foo, b=bar, c=baz.
     * Validate values.
     */
    kv = kv_create ();
    ok (kv != NULL,
        "kv_create works");
    ok (kv_put (kv, "a", "foo") == 0,
        "kv_put a=foo works");
    ok (kv_get (kv, "a", &s) == 0 && !strcmp (s, "foo"),
        "kv_get a retrieves correct value");
    ok (kv_put (kv, "b", "bar") == 0,
        "kv_put b=bar works");
    ok (kv_put (kv, "c", "baz") == 0,
        "kv_put c=baz works");
    diag_kv (kv);

    ok (kv_get (kv, "a", &s) == 0 && !strcmp (s, "foo"),
        "kv_get a retrieves correct value");
    ok (kv_get (kv, "b", &s) == 0 && !strcmp (s, "bar"),
        "kv_get b retrieves correct value");
    ok (kv_get (kv, "c", &s) == 0 && !strcmp (s, "baz"),
        "kv_get b retrieves correct value");
    errno = 0;
    ok (kv_get (kv, "d", &s) < 0 && errno == ENOENT,
        "kv_get d fails with ENOENT");

    /* Iterate over entries.
     */
    key = kv_next (kv, NULL);
    ok (key != NULL && !strcmp (key, "a"),
        "kv_next returned correct key");
    s = kv_val (key);
    ok (s != NULL && !strcmp (s, "foo"),
        "kv_val returned correct value");

    key = kv_next (kv, key);
    ok (key != NULL && !strcmp (key, "b"),
        "kv_next returned correct key");
    s = kv_val (key);
    ok (s != NULL && !strcmp (s, "bar"),
        "kv_val returned correct value");

    key = kv_next (kv, key);
    ok (key != NULL && !strcmp (key, "c"),
        "kv_next returned correct key");
    s = kv_val (key);
    ok (s != NULL && !strcmp (s, "baz"),
        "kv_val returned correct value");

    ok (kv_next (kv, key) == NULL,
        "kv_next returned NULL at end");

    /* Create a new copy through kv_copy() and check for equality.
     */
    kv2 = kv_copy (kv);
    ok (kv2 != NULL,
        "kv_copy works");
    ok (kv_equal (kv, kv2),
        "kv_equal says new copy is identical");

    /* Create a new copy through raw "codec" and check for equality.
     */
    ok (kv_raw_encode (kv, &s, &len) == 0,
        "kv_raw_encode works");
    kv3 = kv_raw_decode (s, len);
    ok (kv3 != NULL,
        "kv_raw_decode works");
    ok (kv_equal (kv, kv3),
        "kv_equal says new copy is identical");

    kv_destroy (kv);
    kv_destroy (kv2);
    kv_destroy (kv3);
}

static void empty_object (void)
{
    struct kv *kv, *kv2;
    const char *buf;
    int len;

    kv = kv_create ();
    ok (kv != NULL,
        "kv_create works");
    ok (kv_next (kv, NULL) == NULL,
        "kv_next key=NULL returns NULL");
    ok (kv_raw_encode (kv, &buf, &len) == 0,
        "kv_raw_encode works");

    kv2 = kv_raw_decode (buf, len);
    ok (kv2 != NULL,
        "kv_raw_decode works");
    ok (kv_equal (kv, kv2),
        "kv_equal says they are identical");

    kv_destroy (kv);
    kv_destroy (kv2);
}

static void check_expansion (void)
{
    struct kv *kv;
    char keybuf[64];
    char valbuf[64];
    const char *s;
    int i;

    kv = kv_create ();
    ok (kv != NULL,
        "kv_create works");

    /* Add entries
     * Each entry wil be 32+3 + 1 + 32 + 1 = 69 bytes.
     * Add 100 of them to ensure 4096 byte "chunk size" is exceeded,
     * so object has to grow at least once.
     */
    for (i = 0; i < 100; i++) {
        snprintf (keybuf, sizeof (keybuf), "key%032d", i);
        snprintf (valbuf, sizeof (valbuf), "%032d", i);
        if (kv_put (kv, keybuf, valbuf) < 0)
            break;
    }
    ok (i == 100,
        "kv_put added 100 69-byte entries");

    for (i = 0; i < 100; i++) {
        snprintf (keybuf, sizeof (keybuf), "key%032d", i);
        snprintf (valbuf, sizeof (valbuf), "%032d", i);
        if (kv_get (kv, keybuf, &s) < 0 || strcmp (s, valbuf) != 0)
            break;
    }
    ok (i == 100,
        "kv_get verified 100 69-byte entries");

    kv_destroy (kv);
}

static void bad_parameters (void)
{
    struct kv *kv;
    struct kv *kv2;
    const char *s;
    const char *entry;
    int len;

    /* Create two kv objects:  kv (emtpy), and kv2 (non-empty).
     */
    if (!(kv = kv_create ()))
        BAIL_OUT ("kv_create failed");
    if (!(kv2 = kv_create ()))
        BAIL_OUT ("kv_create failed");
    if (kv_put (kv2, "foo", "bar") < 0)
        BAIL_OUT ("kv_put failed");
    if (!(entry = kv_next (kv2, NULL)))
        BAIL_OUT ("kv_next kv=(one entry) key=NULL returned NULL");

    /* kv_copy
     */
    errno = 0;
    ok (kv_copy (NULL) == NULL && errno == EINVAL,
        "kv_copy kv=NULL fails with EINVAL");

    /* kv_equal
     */
    ok (kv_equal (kv, NULL) == false,
        "kv_equal kv1=NULL returns false");
    ok (kv_equal (NULL, kv) == false,
        "kv_equal kv2=NULL returns false");
    ok (kv_equal (NULL, NULL) == false,
        "kv_equal kv1=NULL kv2=NULL returns false");

    /* kv_put
     */
    errno = 0;
    ok (kv_put (NULL, "foo", "bar") < 0 && errno == EINVAL,
        "kv_put kv=NULL fails with EINVAL");
    errno = 0;
    ok (kv_put (kv, NULL, "bar") < 0 && errno == EINVAL,
        "kv_put key=NULL fails with EINVAL");
    errno = 0;
    ok (kv_put (kv, "", NULL) < 0 && errno == EINVAL,
        "kv_put key="" fails with EINVAL");
    errno = 0;
    ok (kv_put (kv, "foo", NULL) < 0 && errno == EINVAL,
        "kv_put val=NULL fails with EINVAL");

    /* kv_get
     */
    errno = 0;
    ok (kv_get (NULL, "foo", &s) < 0 && errno == EINVAL,
        "kv_get kv=NULL fails with EINVAL");
    errno = 0;
    ok (kv_get (kv, NULL, &s) < 0 && errno == EINVAL,
        "kv_get key=NULL fails with EINVAL");
    errno = 0;
    ok (kv_get (kv, "", &s) < 0 && errno == EINVAL,
        "kv_get key="" fails with EINVAL");

    /* iteration
     */
    ok (kv_next (NULL, entry) == NULL,
       "kv_next kv=NULL returns NULL");
    ok (kv_next (kv2, entry) == NULL,
       "kv_next kv=(one entry) returns NULL");
    ok (kv_next (kv2, entry - 4096) == NULL,
       "kv_next entry=(< lower bound) == NULL");
    ok (kv_next (kv2, entry + 4096) == NULL,
       "kv_next entry=(> upper bound) == NULL");

    ok (kv_val (NULL) == NULL,
       "kv_val entry=NULL returns NULL");

    /* kv_raw_encode
     */
    errno = 0;
    ok (kv_raw_encode (NULL, &s, &len) < 0 && errno == EINVAL,
        "kv_raw_encode kv=NULL fails with EINVAL");
    errno = 0;
    ok (kv_raw_encode (kv, NULL, &len) < 0 && errno == EINVAL,
        "kv_raw_encode buf=NULL fails with EINVAL");
    errno = 0;
    ok (kv_raw_encode (kv, &s, NULL) < 0 && errno == EINVAL,
        "kv_raw_encode len=NULL fails with EINVAL");

    /* kv_raw_decode
     */
    errno = 0;
    ok (kv_raw_decode ("foo\0bar\0", -1) == NULL && errno == EINVAL,
        "kv_raw_decode len=-1 fails with EINVAL");
    errno = 0;
    ok (kv_raw_decode (NULL, 1) == NULL && errno == EINVAL,
        "kv_raw_decode buf=NULL len=1 fails with EINVAL");
    errno = 0;
    ok (kv_raw_decode ("foo\0bar", 7) == NULL && errno == EINVAL,
        "kv_raw_decode buf=(unterm) fails with EINVAL");
    errno = 0;
    ok (kv_raw_decode ("foo\0bar\0foobar\0", 15) == NULL && errno == EINVAL,
        "kv_raw_decode buf=(no delim entry) fails with EINVAL");
    errno = 0;
    ok (kv_raw_decode ("foo\0bar\0\0foobar\0", 16) == NULL && errno == EINVAL,
        "kv_raw_decode buf=(empty key entry) fails with EINVAL");

    kv_destroy (kv);
    kv_destroy (kv2);
}

void key_deletion (void)
{
    struct kv *kv;

    if (!(kv = kv_create ()))
        BAIL_OUT ("kv_create failed");
    ok (kv_put (kv, "foo", "bar") == 0,
        "kv_put foo=bar works");
    ok (kv_delete (kv, "foo") == 0,
        "kv_delete foo works");
    errno = 0;
    ok (kv_delete (kv, "foo") < 0,
        "kv_delete foo a second time fails with ENOENT");
    ok (kv_put (kv, "foo", "baz") == 0,
        "kv_put foo=baz works");

    kv_destroy (kv);
}

void key_update (void)
{
    struct kv *kv;
    const char *val;

    if (!(kv = kv_create ()))
        BAIL_OUT ("kv_create failed");

    ok (kv_put (kv, "foo", "bar") == 0,
        "kv_put foo=bar works");

    /* Update first (only) entry
     */
    ok (kv_put (kv, "foo", "baz") == 0,
        "kv_put foo=baz works");
    ok (kv_get (kv, "foo", &val) == 0 && !strcmp (val, "baz"),
        "kv_get foo returns baz");

    ok (kv_put (kv, "bar", "xxx") == 0,
        "kv_put bar=xxx works");

    /* Update first (of two) entry
     */
    ok (kv_put (kv, "foo", "yyy") == 0,
        "kv_put foo=yyy works");
    ok (kv_get (kv, "foo", &val) == 0 && !strcmp (val, "yyy"),
        "kv_get foo returns yyy");

    /* Update second (of two) entry
     */
    ok (kv_put (kv, "bar", "zzz") == 0,
        "kv_put bar=zzz works");
    ok (kv_get (kv, "bar", &val) == 0 && !strcmp (val, "zzz"),
        "kv_get bar returns zzz");

    ok (kv_put (kv, "baz", "qqq") == 0,
        "kv_put baz=qqq works");

    /* Update second (of three) entry
     */
    ok (kv_put (kv, "bar", "111") == 0,
        "kv_put bar=111 works");
    ok (kv_get (kv, "bar", &val) == 0 && !strcmp (val, "111"),
        "kv_get bar returns 111");

    kv_destroy (kv);
}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);

    simple_test ();
    empty_object ();
    check_expansion ();
    bad_parameters ();
    key_deletion ();
    key_update ();

    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */
