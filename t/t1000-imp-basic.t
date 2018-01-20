#!/bin/sh
#

test_description='IMP basic functionality test

Ensure IMP runs and runs under sudo when SUDO is available.
Also test basic subcommands like "version".
'

# Append --logfile option if FLUX_TESTS_LOGFILE is set in environment:
test -n "$FLUX_TESTS_LOGFILE" && set -- "$@" --logfile
. `dirname $0`/sharness.sh

flux_imp=${SHARNESS_BUILD_DIRECTORY}/src/imp/flux-imp

echo "# Using ${flux_imp}"

test_expect_success 'flux-imp is built and is executable' '
	test -x $flux_imp
'
test_expect_success 'flux-imp returns error when run with no args' '
	test_must_fail $flux_imp 
'
test_expect_success 'flux-imp version works' '
	$flux_imp version | grep "flux-imp v"
'
test_expect_success SUDO 'flux-imp version works under sudo' '
	sudo $flux_imp version | grep "flux-imp v"
'
test_done
