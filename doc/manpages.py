###############################################################
# Copyright 2022 Lawrence Livermore National Security, LLC
# (c.f. AUTHORS, NOTICE.LLNS, COPYING)
#
# This file is part of the Flux resource manager framework.
# For details, see https://github.com/flux-framework.
#
# SPDX-License-Identifier: LGPL-3.0
###############################################################

author = 'This page is maintained by the Flux community.'

# Add man page entries with the following information:
# - Relative file path (without .rst extension)
# - Man page name
# - Man page description
# - Author (use [author])
# - Manual section
man_pages = [
    ('man3/flux_sign_wrap', 'flux_sign_wrap', 'Wrap signed credential', [author], 3),
    ('man3/flux_sign_wrap', 'flux_sign_wrap_as', 'Wrap signed credential', [author], 3),
    ('man3/flux_sign_unwrap', 'flux_sign_unwrap', 'Unwrap signed credential', [author], 3),
    ('man3/flux_sign_unwrap', 'flux_sign_unwrap_anymech', 'Unwrap signed credential', [author], 3),
    ('man3/flux_security_create', 'flux_security_create', 'Create Flux security context', [author], 3),
    ('man3/flux_security_create', 'flux_security_destroy', 'Create Flux security context', [author], 3),
    ('man3/flux_security_last_error', 'flux_security_last_error', 'Get last error string', [author], 3),
    ('man3/flux_security_last_error', 'flux_security_last_errnum', 'Get last error number', [author], 3),
    ('man5/flux-config-security', 'flux-config-security', 'Flux security configuration files', [author], 5),
    ('man5/flux-config-security-imp', 'flux-config-security-imp', 'configure Flux IMP behavior', [author], 5),
    ('man5/flux-config-security-sign', 'flux-config-security-sign', 'configure Flux security signing library', [author], 5),
    ('man8/flux-imp', 'flux-imp', 'Flux Independent Minister of Privilege', [author], 8),
]
