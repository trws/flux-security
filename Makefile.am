SUBDIRS =         src
ACLOCAL_AMFLAGS = -I config
EXTRA_DIST = \
	config/tap-driver.sh \
	DISCLAIMER.LLNS \
	README.md

# coverage
CODE_COVERAGE_IGNORE_PATTERN = \
        "/t/*" \
	"libtap/*" \
	"/usr/*"
CODE_COVERAGE_LCOV_OPTIONS =
@CODE_COVERAGE_RULES@
