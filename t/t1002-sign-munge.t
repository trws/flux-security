#!/bin/sh
#

test_description='sign-munge tests

Start munge daemon if available and test basic functionality
of sign-munge mechanism.
'

export MUNGED=munged

# Append --logfile option if FLUX_TESTS_LOGFILE is set in environment:
test -n "$FLUX_TESTS_LOGFILE" && set -- "$@" --logfile
. `dirname $0`/sharness.sh

if ! ${MUNGED} --version; then
	skip_all="${MUNGED} could not be executed.  Skipping all tests"
	test_done
fi

sign=${SHARNESS_BUILD_DIRECTORY}/t/src/sign
xsign=${SHARNESS_BUILD_DIRECTORY}/t/src/xsign_munge
verify=${SHARNESS_BUILD_DIRECTORY}/t/src/verify
export FLUX_IMP_CONFIG_PATTERN=${SHARNESS_TRASH_DIRECTORY}/*.toml

# Export this for xsign_munge util
export MUNGE_SOCKET

test_expect_success 'start munged' '
	munged_start_daemon
'

test_expect_success 'munge works' '
	munge --socket ${MUNGE_SOCKET} </dev/null \
		| unmunge --socket ${MUNGE_SOCKET} >/dev/null
'

test_expect_success 'create sign.toml' '
	cat >sign.toml <<-EOT
	[sign]
	max-ttl = 60
	default-type = "munge"
	allowed-types = [ "munge" ]
	[sign.munge]
	socket-path = "${MUNGE_SOCKET}"
	EOT
'

test_expect_success 'sign/verify zero length payload' '
	cat /dev/null >zsign.in &&
	${sign} <zsign.in >zsign.out &&
	${verify} <zsign.out >zverify.out &&
	test_cmp zsign.in zverify.out
'

test_expect_success 'sign/verify a short message' '
	echo Hello >sign.in &&
	${sign} <sign.in >sign.out &&
	${verify} <sign.out >verify.out &&
	test_cmp sign.in verify.out
'

test_expect_success 'verify a hand-created test message' '
	${xsign} good </dev/null >good.out &&
	${verify} <good.out
'

test_expect_success 'message with wrong userid fails verify' '
	${xsign} xuser </dev/null >xuser.out &&
	test_must_fail ${verify} <xuser.out
'

test_expect_success 'message with unknown hash type fails verify' '
	${xsign} xhashtype </dev/null >xhashtype.out &&
	test_must_fail ${verify} <xhashtype.out
'

test_expect_success 'message with truncated hash fails verify' '
	${xsign} xhashtrunc </dev/null >xhashtrunc.out &&
	test_must_fail ${verify} <xhashtrunc.out
'

test_expect_success 'message with altered hash fails verify' '
	${xsign} xhashchg </dev/null >xhashchg.out &&
	test_must_fail ${verify} <xhashchg.out
'

test_expect_success 'message with altered payload fails verify' '
	${xsign} xpaychg </dev/null >xpaychg.out &&
	test_must_fail ${verify} <xpaychg.out
'

test_expect_success 'message with altered munge cred fails verify' '
	${xsign} xcredchg </dev/null >xcredchg.out &&
	test_must_fail ${verify} <xcredchg.out
'

# N.B. max-ttl = (exactly) -100 is allowed for testing
test_expect_success 'create sign.toml with max-ttl=-100' '
	cat >sign.toml <<-EOT
	[sign]
	max-ttl = -100
	default-type = "munge"
	allowed-types = [ "munge" ]
	[sign.munge]
	socket-path = "${MUNGE_SOCKET}"
	EOT
'

test_expect_success 'message with expired TTL fails verify' '
	cat /dev/null >zttl.in &&
	${sign} <zttl.in >zttl.out &&
	test_must_fail ${verify} <zttl.out
'

test_expect_success 'create sign.toml with bogus entry' '
	cat >sign.toml <<-EOT
	[sign]
	max-ttl = 60
	default-type = "munge"
	allowed-types = [ "munge" ]
	[sign.munge]
	socket-path = "${MUNGE_SOCKET}"
	bogus = 42
	EOT
'

test_expect_success 'init fails with bad [sign.munge] config' '
	test_must_fail ${sign} </dev/null
'

test_expect_success 'stop munged' '
	munged_stop_daemon
'

test_done
