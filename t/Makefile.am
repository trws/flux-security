TEST_EXTENSIONS = .t
T_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

TESTS = \
	t0000-sharness.t \
	t0100-sudo-unit-tests.t

check_SCRIPTS = \
	t0000-sharness.t \
	t0100-sudo-unit-tests.t

EXTRA_DIST= \
	sharness.sh \
	sharness.d \
	$(check_SCRIPTS)

clean-local:
	rm -fr trash-directory.* test-results .prove
