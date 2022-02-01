===================
flux_sign_unwrap(3)
===================


SYNOPSIS
========

::

   enum {
       FLUX_SIGN_NOVERIFY = 1,
   };


   int flux_sign_unwrap (flux_security_t *ctx,
                         const char *input,
                         const void **buf,
                         int *len,
                         int64_t *userid,
                         int flags);

   int flux_sign_unwrap_anymech (flux_security_t *ctx,
                                 const char *input,
                                 const void **buf,
                                 int *len,
                                 const char **mech_type,
                                 int64_t *userid,
                                 int flags);


DESCRIPTION
===========

``flux_sign_unwrap()`` verifies the signature of a credential *input*, which
was produced by :man3:`flux_sign_wrap`.  If successful, the payload is
assigned to *buf*, the payload length is assigned to *len*, the signing user
is assigned to *userid*, and the signing mechanism is assigned to *mech_type*.
*flags* may be zero or a bitmask of the following values:

FLUX_SIGN_NOVERIFY
   Allow the function to return success and assign output parameters even if
   the signature verification fails.

Assignment of any of the output parameters may be suppressed by passing in
a NULL value.

``flux_sign_unwrap_anymech()`` is identical to ``flux_sign_unwrap()``, except
that signature verification can succeed even if the mechanism is not one of
the configured allowed types.


RETURN VALUE
============

``flux_sign_unwrap()`` and ``flux_sign_unwrap_anymech()`` return 0 on success,
or -1 on failure with errno set.  In addition, a human readable error string
may be retrieved using :man3:`flux_security_last_error`.


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

:man3:`flux_security_create`, :man3:`flux_security_wrap`,
:man3:`flux_security_last_error`, :man5:`flux-config-security-sign`
