AM_CFLAGS = \
	$(WARNING_CFLAGS) \
	-Wno-sign-compare -Wno-unused-parameter -Wno-parentheses \
	$(JANSSON_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS = \
	$(CODE_COVERAGE_LIBS)

AM_CPPFLAGS = \
	-I$(top_srcdir)

noinst_LTLIBRARIES = \
	libutil.la

libutil_la_SOURCES = \
	base64.c \
	base64.h \
	thread.h \
	hash.c \
	hash.h \
	tomltk.c \
	tomltk.h \
	cf.c \
	cf.h

TESTS = \
	test_base64.t \
	test_hash.t \
	test_tomltk.t

test_ldadd = \
	$(top_builddir)/src/libutil/libutil.la \
	$(top_builddir)/src/libtomlc99/libtomlc99.la \
	$(top_builddir)/src/libtap/libtap.la \
	$(JANSSON_LIBS)

test_cppflags = \
	$(AM_CPPFLAGS)

check_PROGRAMS = $(TESTS)

TEST_EXTENSIONS = .t
T_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

test_base64_t_SOURCES = test/base64_test.c
test_base64_t_CPPFLAGS = $(test_cppflags)
test_base64_t_LDADD = $(test_ldadd)

test_hash_t_SOURCES = test/hash.c
test_hash_t_CPPFLAGS = $(test_cppflags)
test_hash_t_LDADD = $(test_ldadd)

test_tomltk_t_SOURCES = test/tomltk.c
test_tomltk_t_CPPFLAGS = $(test_cppflags)
test_tomltk_t_LDADD = $(test_ldadd)
