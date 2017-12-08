#ifndef _UTIL_CF_H
#define _UTIL_CF_H

#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>

// flags for cf_update
enum {
    CF_STRICT = 1,     // parse error on unknown keys
    CF_ANYTAB = 2,     // allow unknown keys for tables only
};

// allowed types
enum cf_type {
    CF_UNKNOWN      = 0,
    CF_INT64        = 1,
    CF_DOUBLE       = 2,
    CF_BOOL         = 3,
    CF_STRING       = 4,
    CF_TIMESTAMP    = 5,
    CF_TABLE        = 6,
    CF_ARRAY        = 7,
};

typedef void cf_t;

struct cf_option {
    const char *key;
    enum cf_type type;
    bool required;
};
#define CF_OPTIONS_TABLE_END { NULL, 0, false }

struct cf_error {
    char filename[PATH_MAX + 1];
    int lineno;
    char errbuf[200];
};

cf_t *cf_create (void);
void cf_destroy (cf_t *cf);
cf_t *cf_copy (cf_t *cf);
enum cf_type cf_typeof (cf_t *cf);

cf_t *cf_get_in (cf_t *cf, const char *key);
cf_t *cf_get_at (cf_t *cf, int index);

int64_t cf_int64 (cf_t *cf);
double cf_double (cf_t *cf);
const char *cf_string (cf_t *cf);
bool cf_bool (cf_t *cf);
time_t cf_timestamp (cf_t *cf);

int cf_array_size (cf_t *cf);

/* Update table 'cf' with info parsed from TOML 'buf' or 'filename'.
 * On success return 0.  On failure, return -1 with errno set.
 * If error is non-NULL, write error description there.
 */
int cf_update (cf_t *cf, const char *buf, int len, struct cf_error *error);
int cf_update_file (cf_t *cf, const char *filename, struct cf_error *error);

/* Apply 'opts' to table 'cf' according to flags.
 * On success return 0.  On failure, return -1 with errno set.
 * If error is non-NULL, write error description there.
 */
int cf_check (cf_t *cf, const struct cf_option opts[], int flags,
              struct cf_error *error);

#endif /* !_UTIL_CF_H */

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
