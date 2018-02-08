TEST_EXTENSIONS = .t
T_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

TESTS = \
	t0000-sharness.t \
	t0100-sudo-unit-tests.t \
	t1000-imp-basic.t

check_SCRIPTS = \
	t0000-sharness.t \
	t0100-sudo-unit-tests.t \
	t1000-imp-basic.t

check_PROGRAMS = \
	src/keygen \
	src/certutil \
	src/ca

test_cppflags = \
	-I$(top_srcdir)

test_ldadd = \
	$(top_builddir)/src/libutil/libutil.la \
	$(top_builddir)/src/libtomlc99/libtomlc99.la \
	$(top_builddir)/src/imp/testconfig.o

src_keygen_SOURCES = src/keygen.c
src_keygen_CPPFLAGS = $(test_cppflags)
src_keygen_LDADD = $(test_ldadd)

src_certutil_SOURCES = src/certutil.c
src_certutil_CPPFLAGS = $(test_cppflags)
src_certutil_LDADD = $(test_ldadd)

src_ca_SOURCES = src/ca.c
src_ca_CPPFLAGS = $(test_cppflags)
src_ca_LDADD = $(test_ldadd)

EXTRA_DIST= \
	sharness.sh \
	sharness.d \
	$(check_SCRIPTS)

clean-local:
	rm -fr trash-directory.* test-results .prove
