AM_CFLAGS = \
	$(WARNING_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS = \
	$(CODE_COVERAGE_LIBS)

AM_CPPFLAGS = \
	-I$(top_srcdir)

noinst_LTLIBRARIES = \
	libflux-security.la

libflux_security_la_SOURCES = \
	sigcert.c \
	sigcert.h
