AM_CFLAGS = \
	$(WARNING_CFLAGS) \
	-Wno-unused-parameter \
	$(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS = \
	$(CODE_COVERAGE_LIBS) \
	$(SODIUM_LIBS) $(JANSSON_LIBS)

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	$(SODIUM_CFLAGS) $(JANSSON_CFLAGS)

noinst_LTLIBRARIES = \
	libflux-security.la

libflux_security_la_SOURCES = \
	sigcert.c \
	sigcert.h

TESTS = test_sigcert.t

check_PROGRAMS = \
	test_keygen \
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

test_sigcert_t_SOURCES = test/sigcert.c
test_sigcert_t_LDADD = $(test_ldadd)
test_sigcert_t_CPPFLAGS = $(test_cppflags)

test_keygen_SOURCES = test/keygen.c
test_keygen_LDADD = $(test_ldadd)
test_keygen_CPPFLAGS = $(test_cppflags)
