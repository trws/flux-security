========================
flux_security_aux_set(3)
========================


SYNOPSIS
========

::

   #include <flux/security/context.h>

   typedef void (*flux_security_free_f)(void *arg);

   int flux_security_aux_set (flux_security_t *ctx,
                              const char *name,
                              void *data,
                              flux_security_free_f destroy);

   void *flux_security_aux_get (flux_security_t *ctx,
                                const char *name);


DESCRIPTION
===========

``flux_security_aux_set()`` attaches application-specific data to the parent
object *ctx*. It stores *data* by key *name*, with optional destructor
*destroy*. The destructor, if non-NULL, is called when the parent object is
destroyed, or when *name* is overwritten by a new value. If *data* is NULL,
the destructor for a previous value, if any is called, but no new value is
stored. If *name* is NULL, *data* is stored anonymously.

``flux_security_aux_get()`` retrieves application-specific data by *name*.
If the data was stored anonymously, it cannot be retrieved.


RETURN VALUE
============

``flux_security_aux_get()`` returns data on success, or NULL on failure,
with errno set.

``flux_security_aux_set()`` returns 0 on success, or -1 on failure, with
errno set.


ERRORS
======

EINVAL
   Some arguments were invalid.

ENOMEM
   Out of memory.

ENOENT
   ``flux_security_aux_get()`` could not find an entry for *key*.


RESOURCES
=========

Flux: http://flux-framework.org


SEE ALSO
========

:man3:`flux_security_create`
