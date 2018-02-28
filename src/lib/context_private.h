#ifndef _FLUX_SECURITY_CONTEXT_PRIVATE_H
#define _FLUX_SECURITY_CONTEXT_PRIVATE_H

#include <stdarg.h>

/* Capture errno in ctx->errno, and an error message in ctx->error.
 * If 'fmt' is non-NULL, build message; otherwise use strerror (errno).
 */
void security_error (flux_security_t *ctx, const char *fmt, ...);

#endif /* !_FLUX_SECURITY_CONTEXT_PRIVATE_H */
