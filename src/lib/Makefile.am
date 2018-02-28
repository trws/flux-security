AM_CFLAGS = \
	$(WARNING_CFLAGS) \
	-Wno-unused-parameter \
	$(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS = \
	$(CODE_COVERAGE_LIBS) \
	$(SODIUM_LIBS) $(JANSSON_LIBS)

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-DINSTALLED_CF_PATTERN=\"$(fluxcfdir)/*.toml\" \
	$(SODIUM_CFLAGS) $(JANSSON_CFLAGS)

noinst_LTLIBRARIES = \
	libflux-security.la

libflux_security_la_SOURCES = \
	context.c \
	context_private.h

fluxsecurityinclude_HEADERS = \
	context.h

check_PROGRAMS = \
	$(TESTS)

TEST_EXTENSIONS = .t
T_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

test_cppflags = \
	$(AM_CPPFLAGS)

test_ldadd = \
	$(top_builddir)/src/lib/libflux-security.la \
	$(top_builddir)/src/libtomlc99/libtomlc99.la \
	$(top_builddir)/src/libutil/libutil.la \
	$(top_builddir)/src/libtap/libtap.la
