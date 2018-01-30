#ifndef _UTIL_KV_H
#define _UTIL_KV_H

/* Simple serialization (keys and values are encoded as strings):
 *   key\0Tvalue\0key\0Tvalue\0...key\0Tvalue\0
 *
 * T=single-char type hint:
 *   s=string, i=int64_t, d=double, b=bool, t=timestamp
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h> // time_t

enum kv_type {
    KV_UNKNOWN = 0,
    KV_STRING = 's',
    KV_INT64 = 'i',
    KV_DOUBLE = 'd',
    KV_BOOL = 'b',
    KV_TIMESTAMP = 't',
};

/* Create/destroy/copy kv object.
 */
struct kv *kv_create (void);
void kv_destroy (struct kv *kv);
struct kv *kv_copy (const struct kv *kv);

/* Add kv2 entries to kv1, prepending 'prefix' to its keys (if non-NULL).
 * When there are key conflicts, values from kv2 override kv1.
 * Return 0 on success, -1 on failure with errno set.
 */
int kv_join (struct kv *kv1, const struct kv *kv2, const char *prefix);

/* Find entries in kv with matching key prefix.  Create new kv object,
 * consisting of these entries with key prefix removed.
 * Returns new kv object on success, NULL on failure with errno set.
 */
struct kv *kv_split (const struct kv *kv, const char *prefix);

/* Return true if kv1 is identical to kv2 (including entry order)
 */
bool kv_equal (const struct kv *kv1, const struct kv *kv2);

/* Remove 'key' from kv object.
 * Return 0 on success, -1 on failure with errno set.
 *   EINVAL - invalid argument
 *   ENOENT - key not found
 */
int kv_delete (struct kv *kv, const char *key);

/* Add key=val to kv object.
 * N.B. take care that KV_INT64 and KV_TIMESTAMP arguments are the expected
 * size, remembering that default integer argument promotion is to "int".
 * Return 0 on success, -1 on failure with errno set:
 *   EINVAL - invalid argument
 *   ENOMEM - out of memory
 */
int kv_vput (struct kv *kv, const char *key, enum kv_type type, va_list ap);
int kv_put (struct kv *kv, const char *key, enum kv_type type, ...);

/* Find key in kv object and get val (if non-NULL).
 * Return 0 on success, -1 on failure with errno set:
 *   EINVAL - invalid argument
 *   ENOENT - key of requested type not found
 */
int kv_vget (const struct kv *kv, const char *key,
             enum kv_type type, va_list ap);
int kv_get (const struct kv *kv, const char *key, enum kv_type type, ...);

/* Access internal binary encoding.
 * Return 0 on success, -1 on failure with errno set.
 */
int kv_encode (const struct kv *kv, const char **buf, int *len);

/* Create kv object from binary encoding.
 * Return kv object on success, NULL on failure with errno set.
 */
struct kv *kv_decode (const char *buf, int len);

/* Iteration example:
 *
 *   const char *key = NULL;
 *
 *   while ((key = kv_next (kv, key))) {
 *       const char *val = kv_val_string (key);
 *       ...
 *   }
 *
 * kv_delete() may not be called on kv during iteration.
 */
const char *kv_next (const struct kv *kv, const char *key);
enum kv_type kv_typeof (const char *key);

/* Iteration value accessors for keys returned by kv_next().
 * Use kv_typeof() to choose the proper accessor; if type doesn't
 * match, returned value is undefined.
 */
const char *kv_val_string (const char *key); // N.B. never returns NULL
int64_t kv_val_int64 (const char *key);
double kv_val_double (const char *key);
bool kv_val_bool (const char *key);
time_t kv_val_timestamp (const char *key);


#endif /* !_UTIL_KV_H */

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
