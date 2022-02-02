===========================
flux_security_last_error(3)
===========================


SYNOPSIS
========

::

   #include <flux/security/context.h>

   const char *flux_security_last_error (flux_security_t *ctx);

   int flux_security_last_errnum (flux_security_t *ctx);


DESCRIPTION
===========

``flux_security_last_error()`` returns a human readable error message
string for the last error that occurred in the security context.
If there was no error, this function returns NULL.

``flux_security_last_errnum()`` returns a POSIX errno value for the last
error that occurred in the security context.  If there was no error,
this function returns zero.


RESOURCES
=========

Flux: http://flux-framework.org

RFC 15: Independent Minister of Privilege for Flux: The Security IMP: https://flux-framework.readthedocs.io/projects/flux-rfc/en/latest/spec_15.html


SEE ALSO
========

:man3:`flux_security_create`
