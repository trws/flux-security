#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <glob.h>
#include <limits.h>
#include <libgen.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

#include "src/libtap/tap.h"
#include "toml.h"

#define EX1 "\
[server]\n\
    host = \"www.example.com\"\n\
    port = 80\n\
    verbose = false\n\
    timeout = 1.5E3\n\
"

bool validate_toml_table (toml_table_t *conf, char *errbuf, int errsize);
bool validate_toml_array (toml_array_t *array, char *errbuf, int errsize);
bool validate_toml_value (const char *raw, char *errbuf, int errsize);

void parse_ex1 (void)
{
    char errbuf[255];
    toml_table_t *conf;
    toml_table_t *server;
    const char *raw;
    char *host;
    int64_t port;
    int verbose;
    double timeout;
    int rc;

    conf = toml_parse (EX1, errbuf, sizeof (errbuf));
    ok (conf != NULL,
        "ex1: parsed simple example");

    server = toml_table_in (conf, "server");
    ok (server != NULL,
        "ex1: located server table");

    raw = toml_raw_in (server, "host");
    ok (raw != NULL,
        "ex1: located host in server table");
    host = NULL;
    rc = toml_rtos (raw, &host);
    ok (rc == 0,
        "ex1: extracted host string");
    is (host, "www.example.com",
        "ex1: host string has expected value");

    raw = toml_raw_in (server, "port");
    ok (raw != NULL,
        "ex1: located port in server table");
    port = 0;
    rc = toml_rtoi (raw, &port);
    ok (rc == 0,
        "ex1: extracted port int");
    ok (port == 80,
        "ex1: port int has expected value");

    raw = toml_raw_in (server, "verbose");
    ok (raw != NULL,
        "ex1: located verbose in server table");
    verbose = 2;
    rc = toml_rtob (raw, &verbose);
    ok (rc == 0,
        "ex1: extracted verbose boolean");
    ok (verbose == 0,
        "ex1: verbose boolean has expected value");

    raw = toml_raw_in (server, "timeout");
    ok (raw != NULL,
        "ex1: located timeout in server table");
    timeout = 0;
    rc = toml_rtod (raw, &timeout);
    ok (rc == 0,
        "ex1: extracted timeout double");
    ok (timeout == 1.5E3,
        "ex1: timeout double has expected value");

    toml_free (conf);
    free (host);
}

bool validate_toml_value (const char *raw, char *errbuf, int errsize)
{
    char *str;
    int i;
    int64_t i64;
    double d;
    struct toml_timestamp_t ts;

    if (toml_rtos (raw, &str) == 0) {
        free (str);
        return true;
    }
    else if (toml_rtob (raw, &i) == 0)
        return true;
    else if (toml_rtoi (raw, &i64) == 0)
        return true;
    else if (toml_rtod (raw, &d) == 0)
        return true;
    else if (toml_rtots (raw, &ts) == 0)
        return true;

    snprintf (errbuf, errsize, "%s is an invalid value", raw);
    return false;
}

bool validate_toml_array (toml_array_t *array, char *errbuf, int errsize)
{
    int i;
    const char *raw;
    toml_array_t *arr;
    toml_table_t *tab;

    switch (toml_array_kind (array)) {
        case 'v':
            for (i = 0; (raw = toml_raw_at (array, i)); i++) {
                if (!validate_toml_value (raw, errbuf, errsize))
                    return false;
            }
            break;
        case 'a':
            for (i = 0; (arr = toml_array_at (array, i)); i++) {
                if (!validate_toml_array (arr, errbuf, errsize))
                    return false;
            }
            break;
        case 't':
            for (i = 0; (tab = toml_table_at (array, i)); i++) {
                if (!validate_toml_table (tab, errbuf, errsize))
                    return false;
            }
            break;
    }
    return true;
}

bool validate_toml_table (toml_table_t *conf, char *errbuf, int errsize)
{
    int i;
    const char *key;
    const char *raw;
    toml_array_t *arr;
    toml_table_t *tab;

    for (i = 0; (key = toml_key_in (conf, i)); i++) {
        if ((raw = toml_raw_in (conf, key))) { // value
            if (!validate_toml_value (raw, errbuf, errsize))
                return false;
        }
        else if ((arr = toml_array_in (conf, key))) { // array
            if (!validate_toml_array (arr, errbuf, errsize))
                return false;
        }
        else if ((tab = toml_table_in (conf, key))) { // table
            if (!validate_toml_table (tab, errbuf, errsize))
                return false;
        }
        else {
            snprintf (errbuf, errsize, "key=%s is invalid", key);
            return false;
        }
    }
    return true;
}

/* return true if file can be opened and parsing fails
 */
bool parse_bad_file (const char *path, char *errbuf, int errsize)
{
    FILE *fp;
    toml_table_t *conf = NULL;

    if (!(fp = fopen (path, "r"))) {
        snprintf (errbuf, errsize, "%s", strerror (errno));
        return false;
    }
    conf = toml_parse_file (fp, errbuf, errsize);
    if (conf != NULL) {
        if (validate_toml_table (conf, errbuf, errsize)) {
            toml_free (conf);
            fclose (fp);
            snprintf (errbuf, errsize, "success");
            return false;
        }
        toml_free (conf);
    }
    fclose (fp);
    return true;
}

struct entry {
    char *name;
    char *reason;
};

const struct entry bad_input_blacklist[] = {
    { NULL, NULL },
};

bool matchtab (const char *name, const struct entry tab[], const char **reason)
{
    int i;
    for (i = 0; tab[i].name != NULL; i++)
        if (!strcmp (tab[i].name, name)) {
            *reason = tab[i].reason;
            return true;
        }
    return false;
}

void parse_bad_input (void)
{
    char pattern[PATH_MAX];
    int flags = 0;
    glob_t results;
    unsigned i;

    snprintf (pattern, sizeof (pattern), "%s/*.toml", TEST_BAD_INPUT);
    if (glob (pattern, flags, NULL, &results) != 0)
        BAIL_OUT ("glob %s failed - test input not found", pattern);
    diag ("%d files in %s", results.gl_pathc, TEST_BAD_INPUT);

    for (i = 0; i < results.gl_pathc; i++) {
        char errbuf[255];
        char *name = basename (results.gl_pathv[i]);
        const char *reason;
        bool blacklisted = matchtab (name, bad_input_blacklist, &reason);

        skip (blacklisted, 1, "%s: %s", name, reason);
        ok (parse_bad_file (results.gl_pathv[i], errbuf, 255) == true,
            "%s: %s", name, errbuf);
        end_skip;
    }

    globfree (&results);
}

/* return true if file can be opened and parsed
 */
bool parse_good_file (const char *path, char *errbuf, int errsize)
{
    FILE *fp;
    toml_table_t *conf = NULL;


    if (!(fp = fopen (path, "r"))) {
        snprintf (errbuf, errsize, "%s", strerror (errno));
        return false;
    }
    conf = toml_parse_file (fp, errbuf, errsize);
    if (conf == NULL) {
        fclose (fp);
        return false;
    }
    if (!validate_toml_table (conf, errbuf, errsize)) {
        fclose (fp);
        toml_free (conf);
        return false;
    }
    toml_free (conf);
    fclose (fp);
    snprintf (errbuf, errsize, "success");
    return true;
}

void parse_good_input (void)
{
    char pattern[PATH_MAX];
    int flags = 0;
    glob_t results;
    unsigned i;

    snprintf (pattern, sizeof (pattern), "%s/*.toml", TEST_GOOD_INPUT);
    if (glob (pattern, flags, NULL, &results) != 0)
        BAIL_OUT ("glob %s failed - test input not found", pattern);
    diag ("%d files in %s", results.gl_pathc, TEST_GOOD_INPUT);

    for (i = 0; i < results.gl_pathc; i++) {
        char errbuf[255];
        ok (parse_good_file (results.gl_pathv[i], errbuf, 255) == true,
            "%s: %s", basename (results.gl_pathv[i]), errbuf);
    }
}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);

    parse_ex1 ();

    parse_good_input ();
    parse_bad_input ();

    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */
