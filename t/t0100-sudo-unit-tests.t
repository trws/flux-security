#!/bin/sh
#

test_description='Run unit tests that require sudo

Some unit tests in the flux-security project may require sudo support
to work properly. During an automated test run, their execution is deferred
until this script, since it is not possible to run them directly under
`make check` in their srcdir.
'
. `dirname $0`/sharness.sh

basedir=${SHARNESS_BUILD_DIRECTORY}/src

test_expect_success SUDO 'privsep unit tests' '
	sudo $basedir/imp/test_privsep.t
'
test_done
