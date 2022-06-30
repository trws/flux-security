/************************************************************\
 * Copyright 2022 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#ifdef HAVE_LINUX_MAGIC_H
#include <linux/magic.h>
#endif

#include <pwd.h>
#include <signal.h>

#include "src/libutil/strlcpy.h"

#include "pidinfo.h"
#include "imp_log.h"

struct cgroup_info {
    char mount_dir[PATH_MAX + 1];
    bool unified;
};

/*  Determine if this system is using the unified (v2) or legacy (v1)
 *   cgroups hierarchy (See https://systemd.io/CGROUP_DELEGATION/)
 *   and mount point for systemd managed cgroups.
 */
static int cgroup_info_init (struct cgroup_info *cg)
{
    struct statfs fs;

    (void) strlcpy (cg->mount_dir, "/sys/fs/cgroup", sizeof (cg->mount_dir));
    cg->unified = true;

    if (statfs (cg->mount_dir, &fs) < 0)
        return -1;

#ifdef CGROUP2_SUPER_MAGIC
    /* if cgroup2 fs mounted: unified hierarchy for all users of cgroupfs
     */
    if (fs.f_type == CGROUP2_SUPER_MAGIC)
        return 0;
#endif /* CGROUP2_SUPER_MAGIC */

    /*  O/w, if /sys/fs/cgroup is mounted as tmpfs, we need to check
     *   for /sys/fs/cgroup/systemd mounted as cgroupfs (legacy).
     *   We do not support hybrid mode (/sys/fs/cgroup/systemd or
     *   /sys/fs/cgroup/unified mounted as cgroup2fs), since there were
     *   no systems on which to test this configuration.
     */
    if (fs.f_type == TMPFS_MAGIC) {

        (void) strlcpy (cg->mount_dir,
                        "/sys/fs/cgroup/systemd",
                        sizeof (cg->mount_dir));
        if (statfs (cg->mount_dir, &fs) == 0
            && fs.f_type == CGROUP_SUPER_MAGIC) {
            cg->unified = false;
            return 0;
            }
    }

    /*  Unable to determine cgroup mount point and/or unified vs legacy */
    return -1;
}

/*
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
    struct cgroup_info cgroup;

    if (cgroup_info_init (&cgroup) < 0)
        return -1;

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
        if (cgroup.unified || strcmp (subsys, "name=systemd") == 0) {
            n = snprintf (buf, len, "%s%s", cgroup.mount_dir, relpath);
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

void pid_info_destroy (struct pid_info *pi)
{
    free (pi);
}

struct pid_info *pid_info_create (pid_t pid)
{
    struct pid_info *pi;

    if (pid == 0) {
        errno = EINVAL;
        return NULL;
    }
    if (!(pi = calloc (1, sizeof (*pi))))
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

/*
 * vi: ts=4 sw=4 expandtab
 */
