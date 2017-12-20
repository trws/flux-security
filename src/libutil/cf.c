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
#include <errno.h>
#include <string.h>
#include <jansson.h>

#include "src/libtomlc99/toml.h"
#include "tomltk.h"
#include "cf.h"

#define ERRBUFSZ 200

cf_t *cf_create (void)
{
    cf_t *cf;

    if (!(cf = json_object ())) {
        errno = ENOMEM;
        return NULL;
    }
    return cf;
}

void cf_destroy (cf_t *cf)
{
    if (cf) {
        json_decref (cf);
    }
}

cf_t *cf_copy (cf_t *cf)
{
    cf_t *cpy;

    if (!cf) {
        errno = EINVAL;
        return NULL;
    }
    if (!(cpy = json_deep_copy (cf))) {
        errno = ENOMEM;
        return NULL;
    }
    return cpy;
}

static void __attribute__ ((format (printf, 4, 5)))
errprintf (struct cf_error *error,
           const char *filename, int lineno,
            const char *fmt, ...)
{
    va_list ap;
    int saved_errno = errno;

    if (error) {
        memset (error, 0, sizeof (*error));
        va_start (ap, fmt);
        (void)vsnprintf (error->errbuf, sizeof (error->errbuf), fmt, ap);
        va_end (ap);
        if (filename)
            strncpy (error->filename, filename, PATH_MAX);
        error->lineno = lineno;
    }
    errno = saved_errno;
}

struct typedesc {
    enum cf_type type;
    const char *desc;
};

static const struct typedesc typetab[] = {
    { CF_INT64, "int64" },
    { CF_DOUBLE, "double" },
    { CF_BOOL, "bool" },
    { CF_STRING, "string" },
    { CF_TIMESTAMP, "timestamp" },
    { CF_TABLE, "table" },
    { CF_ARRAY, "array" },
};
const int typetablen = sizeof (typetab) / sizeof (typetab[0]);

const char *cf_typedesc (enum cf_type type)
{
    int i;
    for (i = 0; i < typetablen; i++)
        if (typetab[i].type == type)
            return typetab[i].desc;
    return "unknown";
}

enum cf_type cf_typeof (cf_t *cf)
{
    if (!cf)
        return CF_UNKNOWN;
    switch (json_typeof ((json_t *)cf)) {
        case JSON_OBJECT:
            if (tomltk_json_to_epoch (cf, NULL) == 0)
                return CF_TIMESTAMP;
            else
                return CF_TABLE;
        case JSON_ARRAY:
            return CF_ARRAY;
        case JSON_INTEGER:
            return CF_INT64;
        case JSON_REAL:
            return CF_DOUBLE;
        case JSON_TRUE:
        case JSON_FALSE:
            return CF_BOOL;
        case JSON_STRING:
            return CF_STRING;
        default:
            return CF_UNKNOWN;
    }
}

cf_t *cf_get_in (cf_t *cf, const char *key)
{
    cf_t *val;

    if (!cf || cf_typeof (cf) != CF_TABLE || !key) {
        errno = EINVAL;
        return NULL;
    }
    if (!(val = json_object_get (cf, key))) {
        errno = ENOENT;
        return NULL;
    }
    return val;

}

cf_t *cf_get_at (cf_t *cf, int index)
{
    cf_t *val;

    if (!cf || cf_typeof (cf) != CF_ARRAY || index < 0) {
        errno = EINVAL;
        return NULL;
    }
    if (!(val = json_array_get (cf, index))) {
        errno = ENOENT;
        return NULL;
    }
    return val;
}

int64_t cf_int64 (cf_t *cf)
{
    return cf ? json_integer_value (cf) : 0;
}

double cf_double (cf_t *cf)
{
    return cf ? json_real_value (cf) : 0.;
}

const char *cf_string (cf_t *cf)
{
    const char *s = cf ? json_string_value (cf) : NULL;
    return s ? s : "";
}

bool cf_bool (cf_t *cf)
{
    if (cf && json_typeof ((json_t *)cf) == JSON_TRUE)
        return true;
    return false;
}

time_t cf_timestamp (cf_t *cf)
{
    time_t t;
    if (!cf || tomltk_json_to_epoch (cf, &t) < 0)
        return 0;
    return t;
}

int cf_array_size (cf_t *cf)
{
    return cf ? json_array_size (cf) : 0;
}

/* Parse some TOML and merge it with 'cf' object.
 * If filename is non-NULL, take TOML from file, o/w use buf, len.
 */
static int update_object (cf_t *cf,
                          const char *filename,
                          const char *buf, int len,
                          struct cf_error *error)
{
    struct tomltk_error toml_error;
    toml_table_t *tab;
    json_t *obj = NULL;
    int saved_errno;

    if (!cf || json_typeof ((json_t *)cf) != JSON_OBJECT) {
        errprintf (error, filename, -1, "invalid config object");
        errno = EINVAL;
        return -1;
    }
    if (filename)
        tab = tomltk_parse_file (filename, &toml_error);
    else
        tab = tomltk_parse (buf, len, &toml_error);
    if (!tab) {
        errprintf (error, toml_error.filename, toml_error.lineno,
                   "%s", toml_error.errbuf);
        goto error;
    }
    if (!(obj = tomltk_table_to_json (tab))) {
        errprintf (error, filename, -1, "converting TOML to JSON: %s",
                   strerror (errno));
        goto error;
    }
    if (json_object_update (cf, obj) < 0) {
        errprintf (error, filename, -1, "updating JSON object: out of memory");
        errno = ENOMEM;
        goto error;
    }
    json_decref (obj);
    toml_free (tab);
    return 0;
error:
    saved_errno = errno;
    toml_free (tab);
    json_decref (obj);
    errno = saved_errno;
    return -1;
}

int cf_update (cf_t *cf, const char *buf, int len, struct cf_error *error)
{
    return update_object (cf, NULL, buf, len, error);
}

int cf_update_file (cf_t *cf, const char *filename, struct cf_error *error)
{
    return update_object (cf, filename, NULL, 0, error);
}

static bool is_end_marker (struct cf_option opt)
{
    const struct cf_option end = CF_OPTIONS_TABLE_END;
    return (opt.key == end.key
            && opt.type == end.type
            && opt.required == end.required);
}

static const struct cf_option *find_option (const struct cf_option opts[],
                                            const char *key)
{
    int i;
    if (opts) {
        for (i = 0; !is_end_marker (opts[i]); i++) {
            if (!strcmp (opts[i].key, key))
                return &opts[i];
        }
    }
    return NULL;
}

/* Make sure all keys in 'cf' are known in 'opts'.
 * If 'anytab' is true, keys representing tables need not be known.
 */
static int check_unknown_keys (cf_t *cf,
                               const struct cf_option opts[], bool anytab,
                               struct cf_error *error)
{
    void *iter;

    iter = json_object_iter (cf);
    while (iter) {
        const char *key = json_object_iter_key (iter);
        json_t *obj = json_object_get (cf, key);

        if (!find_option (opts, key)) {
            if (!json_is_object (obj) || !anytab) {
                errprintf (error, NULL, -1, "key '%s' is unknown", key);
                errno = EINVAL;
                return -1;
            }
        }
        iter = json_object_iter_next (cf, iter);
    }
    return 0;
}

static int check_expected_keys (cf_t *cf,
                                const struct cf_option opts[],
                                struct cf_error *error)
{
    int i;

    if (opts) {
        for (i = 0; !is_end_marker (opts[i]); i++) {
            json_t *obj = json_object_get (cf, opts[i].key);

            if (!obj && opts[i].required) {
                errprintf (error, NULL, -1, "'%s' must be set", opts[i].key);
                errno = EINVAL;
                return -1;
            }
            if (obj && cf_typeof (obj) != opts[i].type) {
                errprintf (error, NULL, -1, "'%s' must be of type %s",
                           opts[i].key, cf_typedesc (opts[i].type));
                errno = EINVAL;
                return -1;
            }
        }
    }
    return 0;
}

int cf_check (cf_t *cf,
              const struct cf_option opts[], int flags,
              struct cf_error *error)
{
    if (!cf || json_typeof ((json_t *)cf) != JSON_OBJECT) {
        errprintf (error, NULL, -1, "invalid config object");
        errno = EINVAL;
        return -1;
    }
    if ((flags & CF_STRICT)) {
        if (check_unknown_keys (cf, opts, (flags & CF_ANYTAB), error) < 0)
            return -1;
    }
    if (check_expected_keys (cf, opts, error) < 0)
        return -1;
    return 0;
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
