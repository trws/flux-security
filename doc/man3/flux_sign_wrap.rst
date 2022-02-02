=================
flux_sign_wrap(3)
=================


SYNOPSIS
========

::

   #include <flux/security/sign.h>

   const char *flux_sign_wrap (flux_security_t *ctx,
                               const void *buf,
                               int len,
                               const char *mech_type,
                               int flags);

   const char *flux_sign_wrap_as (flux_security_t *ctx,
                                  int64_t userid,
                                  const void *buf,
                                  int len,
                                  const char *mech_type,
                                  int flags);


DESCRIPTION
===========

``flux_sign_wrap()`` wraps a payload defined by *buf* and *len* in a credential
suitable for unwrapping with :man3:`flux_sign_unwrap`.  The signing user is
taken to be the userid returned by :linux:man2:`getuid`.  *ctx* is a Flux
security context from :man3:`flux_security_create`.  *mech_type* selects the
signing mechanism, and may be set to NULL to select the default defined
by :man5:`flux-config-security-sign`.  The *flags* parameter must be set to
zero.  The function returns a NULL terminated credential string that remains
valid until ``flux_sign_wrap()`` is called again.  The caller should not
attempt to free the credential.

``flux_sign_wrap_as()`` is identical to ``flux_sign_wrap()``, except the
signing user may be explicitly specified with the *userid* parameter.


RETURN VALUE
============

``flux_sign_wrap()`` and ``flux_sign_wrap_as()`` return a NULL terminated
credential on success, or NULL on failure with errno set.  In addition, a human
readable error string may be retrieved using :man3:`flux_security_last_error`.


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

:man3:`flux_security_create`, :man3:`flux_security_unwrap`,
:man3:`flux_security_last_error`, :man5:`flux-config-security-sign`
