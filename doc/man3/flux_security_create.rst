=======================
flux_security_create(3)
=======================


SYNOPSIS
========

::

   flux_security_t *flux_security_create (int flags);

   void flux_security_destroy (flux_security_t *ctx);


DESCRIPTION
===========

``flux_security_create()`` creates a Flux security context for use with other
Flux security functions.  *flags* should be set to zero for use outside of
the test environment.

``flux_security_destroy()`` destroys a security context.


RETURN VALUE
============

``flux_security_create()`` returns a Flux security context on success,
or NULL on failure with errno set.


ERRORS
======

EINVAL
   Some arguments were invalid.

ENOMEM
   Out of memory.


RESOURCES
=========

Flux: http://flux-framework.org

RFC 15: Independent Minister of Privilege for Flux: The Security IMP: https://flux-framework.readthedocs.io/projects/flux-rfc/en/latest/spec_15.html


SEE ALSO
========

:man3:`flux_security_last_error`
