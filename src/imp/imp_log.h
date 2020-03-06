/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_IMP_LOG_H
#define HAVE_IMP_LOG_H 1

/*  Initialize IMP logging facility */
void imp_openlog ();

/*  Close logging facility */
void imp_closelog ();

/*  Say a message to standard IMP logging destination(s) */
void imp_say (const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));

/*  Emit warning to IMP logging destination(s) */
void imp_warn (const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));

/*  Issue a debug message to IMP logging destination(s) */
void imp_debug (const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));

/*  Print an error to IMP logging destination and exit with exit `code` */
void __attribute__((noreturn)) imp_die (int code, const char *fmt, ...)
     __attribute__ ((format (printf, 2, 3)));

/*
 *  Logging output provider prototype:
 */
typedef int (*imp_log_output_f) (int level, const char *str, void *arg);

/*  Add a new log provider `fn` as `name` with default log level `level`.
 *  If non-NULL, `arg` is passed to each invocation of `fn`.
 *
 *  Returns 0 on success, < 0 with EEXIST if a provider with `name` already
 *   exists
 */
int imp_log_add (const char *name, int level, imp_log_output_f fn, void *arg);

/*  Remove logging provider `name`. Returns 0 on success, -1 with ENOENT if
 *   no log provider with `name` is registered.
 */
int imp_log_remove (char *name);

/*
 *  Set global or per-provider logging levels. The log provider will not
 *   log messages issued at higher levels than `level` after this call is
 *   made. If `name` is NULL, then the level is applied globally.
 *
 *  Returns 0 on success, -1 on error with errno set.
 *   EINVAL - an invalid logging level was provided.
 *   ENOENT - named log `name` was not found
 */
int imp_log_set_level (const char *name, int level);

/*
 *  Logging types passed to output provider.
 */
#define IMP_LOG_FATAL      0
#define IMP_LOG_WARNING    1
#define IMP_LOG_INFO       2
#define IMP_LOG_DEBUG      3

/*
 *  Return a string representation of the Level `level`
 */
const char *imp_log_strlevel (int level);

#endif /* !HAVE_IMP_LOG_H */
