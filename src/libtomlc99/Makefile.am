AM_CFLAGS = \
	-I$(top_srcdir) \
	$(WARNING_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS = \
	$(CODE_COVERAGE_LIBS)

AM_CPPFLAGS =

noinst_LTLIBRARIES = libtomlc99.la

libtomlc99_la_SOURCES = \
	toml.c \
	toml.h

TESTS =

check_PROGRAMS = \
	toml_cat \
	toml_json \
	$(TESTS)

TEST_EXTENSIONS = .t
T_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

test_ldadd = \
	$(top_builddir)/src/libtomlc99/libtomlc99.la \
	$(top_builddir)/src/libtap/libtap.la

toml_cat_SOURCES = toml_cat.c
toml_cat_LDADD = $(test_ldadd)

toml_json_SOURCES = toml_json.c
toml_json_LDADD = $(test_ldadd)
