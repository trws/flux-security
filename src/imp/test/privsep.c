/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include "imp_log.h"
#include "sudosim.h"
#include "privsep.h"

#include "src/libtap/tap.h"

static void child (privsep_t *ps, void *arg __attribute__ ((unused)))
{
    bool rv;
    uid_t euid = geteuid ();
    uid_t uid = getuid ();
    int len = sizeof (uid_t);

    int n = privsep_write (ps, &euid, len);
    if (n != len) {
        diag ("privsep_write: euid: %s", strerror (errno));
        exit (1);
    }
    n = privsep_write (ps, &uid, len);
    if (n != len) {
        diag ("privsep_write: uid: %s", strerror (errno));
        exit (1);
    }

    /*  Can't use TAP output here (numbering would be incorrect),
     *   instead send result directly to parent over the privsep connection.
     */
    rv = privsep_is_child (ps);
    n = privsep_write (ps, &rv, sizeof (rv));
    if (n != sizeof (rv)) {
        diag ("privsep write: bool: %s", strerror (errno));
        exit (1);
    }

    rv = privsep_is_parent (ps);
    n = privsep_write (ps, &rv, sizeof (rv));
    if (n != sizeof (rv)) {
        diag ("privsep write: bool: %s", strerror (errno));
        exit (1);
    }
    /*  Child exits on return */
}


static void test_privsep_basic (void)
{
    uid_t uid, euid;
    bool result;
    ssize_t len = sizeof (uid_t);
    privsep_t *ps = NULL;

    ok ((ps = privsep_init (child, NULL)) != NULL, "privsep_init");
    if (ps == NULL)
        BAIL_OUT ("privsep_init failed");

    ok (privsep_is_parent (ps), "privsep_is_parent returns true in parent");

    ok (privsep_read (ps, &euid, len) == len,
        "privsep_read: euid from child");
    ok (privsep_read (ps, &uid, len) == len,
        "privsep_read: uid from child");

    ok (euid == getuid (),
        "child has effective uid of parent real uid (euid=%ld)", (long) euid);
    ok (uid == getuid (),
        "child has real uid of parent (uid=%ld)", (long) uid);


    ok (privsep_read (ps, &result, sizeof (result)) == sizeof (result),
        "privsep read: result of privsep_is_child");
    ok (result == true, "privsep_is_child in child returns true");
    ok (privsep_read (ps, &result, sizeof (result)) == sizeof (result),
        "privsep read: result of privsep_is_parent");
    ok (result == false, "privsep_is_parent in child returns false");

    ok (!privsep_is_child (ps), "privsep_is_child in parent returns false");


    ok (geteuid() == 0,
        "parent retains effective uid == 0");

    ok (privsep_destroy (ps) == 0, "privsep child exited normally");
}

static void child_kv_test (privsep_t *ps, void *arg __attribute__ ((unused)))
{
    bool v;
    struct kv *kv = kv_create ();

    /* Send a kv to parent, get same kv back with addition of "parent = true"
     */
    if (!kv)
        imp_die (1, "kv_create");
    if (kv_put (kv, "child", KV_BOOL, true) < 0)
        imp_die (1, "kv_put: %s", strerror (errno));
    if (kv_put (kv, "foo", KV_STRING, "bar") < 0)
        imp_die (1, "kv_put: %s", strerror (errno));

    if (privsep_write_kv (ps, kv) <= 0)
        imp_die (1, "privsep_write_kv: %s", strerror (errno));

    imp_say ("privsep_write_kv complete");

    kv_destroy (kv);

    if (!(kv = privsep_read_kv (ps)))
        imp_die (1, "privsep_read_kv: %s", strerror (errno));

    if (kv_get (kv, "parent", KV_BOOL, &v) < 0)
        imp_die (1, "kv_get ('parent'): %s", strerror (errno));

    if (!v)
        imp_die (1, "parent = 'true' not set in returned kv object");
}

static void test_privsep_kv (void)
{
    privsep_t *ps;
    struct kv *kv;
    bool v;
    const char *s;

    ok ((ps = privsep_init (child_kv_test, NULL)) != NULL,
        "privsep_init");

    if (ps == NULL)
        BAIL_OUT ("privsep_init failed");

    /*  Read kv from child, set parent = 'true' and write back to child */
    ok ((kv = privsep_read_kv (ps)) != NULL, "privsep_read_kv");

    ok ((kv_get (kv, "child", KV_BOOL, &v) >= 0),
        "key 'child' set in obtained kv");
    ok (v, "key 'child' is true");
    ok ((kv_get (kv, "foo", KV_STRING, &s) >= 0),
        "key 'foo' set in obtained kv");
    is (s, "bar", "key 'foo' has correct value");

    ok (kv_put (kv, "parent", KV_BOOL, true) >= 0,
        "set parent = true in kv");

    ok (privsep_write_kv (ps, kv) >= 0,
        "privsep_write_kv");

    ok (privsep_destroy (ps) == 0, "privsep child exited normally");
}

static void child_write_ints (privsep_t *ps, void *arg)
{
    int *z = ((int *) arg);
    privsep_write (ps, &z[0], sizeof (int));
    privsep_write (ps, &z[1], sizeof (int));
    privsep_write (ps, &z[2], sizeof (int));
}

static struct kv *create_yuuuuuge_kv (void)
{
    int i;
    char largeval [4096];
    struct kv *kv = kv_create ();

    memset (largeval, 'x', sizeof (largeval) - 1);
    largeval [4095] = '\0';

    ok (strlen (largeval) == 4095, "Create huge value for oversized kv");

    for (i = 0; i < 1024; i++) {
        char key [5];
        if (sprintf (key, "%04d", i) != 4) {
            imp_warn ("huge_kv: Failed to create key %04d", i);
            goto fail;
        }
        if (kv_put (kv, key, KV_STRING, largeval) < 0) {
            imp_warn ("huge_kv: kv_put: %s", strerror (errno));
            goto fail;
        }
    }
    return (kv);
fail:
    kv_destroy (kv);
    return (NULL);
}

static void test_privsep_kv_bad_input (void)
{
    struct kv *kv;
    int invalid_size[3] = { 1024*1024*4 + 1, 0, -1234 };

    privsep_t *ps = privsep_init (child_write_ints, &invalid_size);

    ok (ps != NULL, "privsep_init");

    /*  Child writes value too large, then too small (0) then much too
     *   small (< 0), Each read should return E2BIG
     */
    ok ((kv = privsep_read_kv (ps)) == NULL && errno == E2BIG,
        "privsep_read fails with invalid size (too large)");
    ok ((kv = privsep_read_kv (ps)) == NULL && errno == E2BIG,
        "privsep_read fails with invalid size (0)");
    ok ((kv = privsep_read_kv (ps)) == NULL && errno == E2BIG,
        "privsep_read fails with invalid size (< 0)");

    ok ((kv = create_yuuuuuge_kv ()) != NULL,
        "created kv of unusual size");
    ok ((privsep_write_kv (ps, kv) < 0) && errno == E2BIG,
        "privsep_write_kv returns E2BIG on very large kv");

    kv_destroy (kv);

    privsep_destroy (ps);
}

static int log_diag (int level, const char *str,
                     void *arg __attribute__ ((unused)))
{
    diag ("privsep: %s: %s\n", imp_log_strlevel (level), str);
    return (0);
}

int main (void)
{
    /*  Privsep code uses imp log for errors, so need to initialize here
     */
    imp_openlog ();
    imp_log_add ("diag", IMP_LOG_DEBUG, log_diag, NULL);

    if (sudo_simulate_setuid () < 0)
        BAIL_OUT ("Failed to simulate setuid under sudo");

    if (geteuid () == getuid ()) {
        plan (SKIP_ALL, "Privsep test needs to be run setuid");
        return (0);
    }

    plan (NO_PLAN);

    test_privsep_basic ();
    test_privsep_kv ();
    test_privsep_kv_bad_input ();

    imp_closelog ();
    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */
