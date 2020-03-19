/************************************************************\
 * Copyright 2020 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/* flux-imp kill - signal tasks on behalf of requestor when authorized
 *
 * PURPOSE:
 *
 *  Allow a non-privileged Flux instance to signal processes in
 *  jobs running as different users.
 *
 * OPERATION:
 *
 *  The IMP kill command currently works under the assumption that the
 *  multiuser instance is running under systemd with Delegate=yes. This
 *  setting directs systemd to delegate ownership of the flux.service
 *  cgroup to the user under which Flux is runnng, e.g. "flux".
 *
 *  Since all jobs will executed within this cgroup or a child,
 *  flux-imp kill may authorize signal delivery to any task where
 *  the tasks cgroup is owned by the requesting user.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <signal.h>

#include "src/libutil/kv.h"

#include "imp_log.h"
#include "imp_state.h"
#include "impcmd.h"
#include "privsep.h"

struct pid_info {
    pid_t pid;
    uid_t pid_owner;
    char cg_path [4096];
    uid_t cg_owner;
};

/*  Hard-coded path to systemd cgroup mount directory. This may
 *   need to be moved to configuration at some point.
 */
static const char cgroup_mount_dir[] = "/sys/fs/cgroup/systemd";

/*  Return the systemd cgroup path for PID `pid` in the provided buffer
 *  Looks up the 'name=systemd'[*] subsystem relative cgroup path in
 *   /proc/PID/cgroups and prepends `cgroup_mount_dir` to get the
 *   full path.
 *
 *  [*] perhaps could also use the "pids" cgroup.
 */
static int pid_systemd_cgroup_path (pid_t pid, char *buf, int len)
{
    int rc = -1;
    FILE *fp;
    size_t size = 0;
    int n;
    char file [4096];
    char *line = NULL;

    n = snprintf (file, sizeof(file), "/proc/%ju/cgroup", (uintmax_t) pid);
    if ((n < 0) || (n >= (int) sizeof(file))
        || !(fp = fopen (file, "r")))
        return -1;

    while ((n = getline (&line, &size, fp)) >= 0) {
        char *nl;
        char *relpath = NULL;
        char *subsys = strchr (line, ':');
        if ((nl = strchr (line, '\n')))
            *nl = '\0';
        if (subsys == NULL || *(++subsys) == '\0'
            || !(relpath = strchr (subsys, ':')))
            continue;
        /* Nullify subsys, relpath is already nul-terminated at newline */
        *(relpath++) = '\0';
        if (strcmp (subsys, "name=systemd") == 0) {
            n = snprintf (buf, len, "%s%s", cgroup_mount_dir, relpath);
            if ((n > 0) && (n < len))
                rc = 0;
            break;
        }
    }

    free (line);
    fclose (fp);
    return rc;
}

/*  return the file owner of 'path'
 */
static uid_t path_owner (const char *path)
{
    struct stat st;
    if (stat (path, &st) < 0)
        return ((uid_t) -1);
    return st.st_uid;
}

/*  return the owner of pid. -1 on failure.
 */
static uid_t pid_owner (pid_t pid)
{
    char path [128];
    const int size = sizeof (path);
    int n = snprintf (path, size, "/proc/%ju", (uintmax_t) pid);
    if ((n < 0) || (n >= size))
        return (pid_t) -1;
    return path_owner (path);
}

static void pid_info_destroy (struct pid_info *pi)
{
    free (pi);
}

static struct pid_info *pid_info_create (pid_t pid)
{
    struct pid_info *pi = calloc (1, sizeof (*pi));
    if (pi == NULL)
        return NULL;
    if (pid < 0)
        pid = -pid;
    pi->pid = pid;
    if ((pi->pid_owner = pid_owner (pid)) == (uid_t) -1)
        goto err;
    if (pid_systemd_cgroup_path (pid, pi->cg_path, sizeof (pi->cg_path)) < 0)
        goto err;
    if ((pi->cg_owner = path_owner (pi->cg_path)) == (uid_t) -1)
        goto err;

    return pi;
err:
    pid_info_destroy (pi);
    return NULL;
}

/*  Return true if the user executing the IMP is allowed to run
 *   'flux-imp kill'. This is the same set of users allowed to run
 *   'flux-imp exec', so look in exec.allowed-users.
 */
static bool imp_kill_allowed (const cf_t *conf)
{
    struct passwd * pwd = getpwuid (getuid ());
    const cf_t *exec = cf_get_in (conf, "exec");

    if (pwd && exec)
        return cf_array_contains (cf_get_in (exec, "allowed-users"),
                                  pwd->pw_name);
    return false;
}

static void check_and_kill_process (struct imp_state *imp, pid_t pid, int sig)
{
    uid_t user = getuid ();
    struct pid_info *p = NULL;

    if (!imp_kill_allowed (imp->conf))
        imp_die (1, "kill command not allowed");

    if (!(p = pid_info_create ((pid_t) pid)))
        imp_die (1, "kill: failed to initialize pid info: %s",
                    strerror (errno));

    /* Check if pid is in pids cgroup owned by IMP user */
    if (p->cg_owner != user
        && p->pid_owner != user)
        imp_die (1,
            "kill: refusing request from uid=%ju to kill pid %jd (owner=%ju)",
            (uintmax_t) user,
            (intmax_t) pid,
            (uintmax_t) p->cg_owner);

    if (kill (pid, sig) < 0)
        imp_die (1, "kill: %jd sig=%ju: %s",
                    (intmax_t) pid,
                    (uintmax_t) sig,
                    strerror (errno));

    pid_info_destroy (p);
}


/*  Read pid and signal from the privsep pipe, then check if user
 *   is allowed to kill the target process.
 */
int imp_kill_privileged (struct imp_state *imp, struct kv *kv)
{
    int64_t pid;
    int64_t signum;

    if (kv_get (kv, "pid", KV_INT64, &pid) < 0)
        imp_die (1, "kill: failed to get pid");
    if (kv_get (kv, "signal", KV_INT64, &signum) < 0)
        imp_die (1, "kill: failed to get signal");

    check_and_kill_process (imp, pid, signum);
    return 0;
}

/*  Unprivileged process reads signal and pid from cmdline and
 *   sends to parent over privsep pipe. If not running privileged,
 *   try killing as requesting user (used for testing).
 */
int imp_kill_unprivileged (struct imp_state *imp, struct kv *kv)
{
    char *p = NULL;
    int64_t pid = 0;
    int64_t signum = -1;

    if (imp->argc < 4)
        imp_die (1, "kill: Usage flux-imp kill SIGNAL PID");

    if ((signum = strtol (imp->argv[2], &p, 10)) <= 0
        || *p != '\0')
        imp_die (1, "kill: invalid SIGNAL %s", imp->argv[2]);

    /*  PID of 0 is explicitly forbidden here as it could be used
     *   to inadvertenly kill our parent.
     */
    if ((pid = strtol (imp->argv[3], &p, 10)) == 0
        || *p != '\0')
        imp_die (1, "kill: invalid PID %s", imp->argv[3]);

    if (kv_put (kv, "pid", KV_INT64, pid) < 0)
        imp_die (1, "kill: kv_put pid: %s", strerror (errno));
    if (kv_put (kv, "signal", KV_INT64, signum) < 0)
        imp_die (1, "kill: kv_put signum: %s", strerror (errno));

    if (!imp->ps)
        check_and_kill_process (imp, pid, signum);
    else if (privsep_write_kv (imp->ps, kv) < 0)
        imp_die (1, "kill: failed to communicate with privsep parent");

    return 0;
}

/* vi: ts=4 sw=4 expandtab
 */
