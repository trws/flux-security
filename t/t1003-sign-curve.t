#!/bin/sh
#

test_description='sign-curve tests

Test basic functionality of sign-curve mechanism.
'

# Append --logfile option if FLUX_TESTS_LOGFILE is set in environment:
test -n "$FLUX_TESTS_LOGFILE" && set -- "$@" --logfile
. `dirname $0`/sharness.sh

flux_imp=${SHARNESS_BUILD_DIRECTORY}/src/imp/flux-imp
keygen=${SHARNESS_BUILD_DIRECTORY}/t/src/keygen
certutil=${SHARNESS_BUILD_DIRECTORY}/t/src/certutil
ca=${SHARNESS_BUILD_DIRECTORY}/t/src/ca
sign=${SHARNESS_BUILD_DIRECTORY}/t/src/sign
verify=${SHARNESS_BUILD_DIRECTORY}/t/src/verify
xsign=${SHARNESS_BUILD_DIRECTORY}/t/src/xsign_curve
prelib="${LD_PRELOAD} ${SHARNESS_BUILD_DIRECTORY}/t/src/.libs/getpwuid.so"
uidlookup=${SHARNESS_BUILD_DIRECTORY}/t/src/uidlookup

export FLUX_IMP_CONFIG_PATTERN=${SHARNESS_TRASH_DIRECTORY}/conf.d/*.toml

config_imp() {
	cat <<-EOT
	allow-sudo = true
	EOT
}

config_sign() {
	cat <<-EOT
	[sign]
	max-ttl = 60
	default-type = "curve"
	allowed-types = [ "curve" ]
	EOT
}

config_sign_curve_ca() {
	cat <<-EOT
	[sign.curve]
	require-ca = true
	cert-path = "${SHARNESS_TRASH_DIRECTORY}/u"
	EOT
}

config_sign_curve_noca() {
	cat <<-EOT
	[sign.curve]
	require-ca = false
	EOT
}

config_ca() {
	cat <<-EOT
	[ca]
	max-cert-ttl = 60
	max-sign-ttl = 30
	cert-path = "${SHARNESS_TRASH_DIRECTORY}/ca"
	revoke-dir = "${SHARNESS_TRASH_DIRECTORY}/revoke.d"
	revoke-allow = true
	domain = "EXAMPLE.TEST"
	EOT
}

test_expect_success 'create config' '
	mkdir -p conf.d &&
	config_imp >conf.d/imp.toml &&
	config_sign >conf.d/sign.toml &&
	config_sign_curve_ca >>conf.d/sign.toml &&
	config_ca >conf.d/ca.toml
'

test_expect_success 'create CA cert' '
	${ca} keygen &&
	test -f ca &&
	test -f ca.pub
'

test_expect_success 'create user signing cert' '
	${keygen} u &&
	${flux_imp} casign <u.pub >u.pub.signed &&
	mv u.pub u.pub.unsigned &&
	mv u.pub.signed u.pub
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

test_expect_success 'switch to un-CA-signed cert' '
	mv u.pub u.pub.signed &&
	mv u.pub.unsigned u.pub
'

test_expect_success 'verify fails when cert was not signed by CA' '
	${sign} </dev/null >xcasign.out &&
	test_must_fail ${verify} <xcasign.out 2>xcasign.err &&
	grep -q "ca: signature verification" xcasign.err
'

test_expect_success 'switch back to CA-signed cert' '
	mv u.pub u.pub.unsigned &&
	mv u.pub.signed u.pub
'

test_expect_success 'verify a hand-created test message' '
	${xsign} u good </dev/null >good.out &&
	${verify} <good.out
'

test_expect_success 'message with wrong userid fails verify' '
	${xsign} u xuser </dev/null >xuser.out &&
        test_must_fail ${verify} <xuser.out 2>xuser.err &&
        grep -q "ca: userid mismatch" xuser.err
'

test_expect_success 'message with altered payload fails verify' '
	${xsign} u xpaychg </dev/null >xpaychg.out &&
	test_must_fail ${verify} <xpaychg.out 2>xpaychg.err &&
	grep -q "verification failure" xpaychg.err
'

test_expect_success 'message with future ctime fails verify' '
	${xsign} u xctime </dev/null >xctime.out &&
	test_must_fail ${verify} <xctime.out 2>xctime.err &&
	grep -q "ctime is in the future" xctime.err
'

test_expect_success 'message with past xtime fails verify' '
	${xsign} u xxtime </dev/null >xxtime.out &&
	test_must_fail ${verify} <xxtime.out 2>xxtime.err &&
	grep -q "xtime or max-ttl exceeded" xxtime.err
'

test_expect_success 'message with incomplete header fails verify' '
	${xsign} u xheader </dev/null >xheader.out &&
	test_must_fail ${verify} <xheader.out 2>xheader.err &&
	grep -q "incomplete header" xheader.err
'

test_expect_success 'message with mech-specific header fails verify' '
	${xsign} u xnoheader </dev/null >xnoheader.out &&
	test_must_fail ${verify} <xnoheader.out 2>xnoheader.err &&
	grep -q "incomplete header" xheader.err
'

test_expect_success 'drop [sign.curve] config' '
	config_sign >conf.d/sign.toml
'

test_expect_success 'sign fails with missing [sign.curve] config' '
	test_must_fail ${sign} </dev/null 2>xconfig.err &&
	grep -q "config missing" xconfig.err
'

test_expect_success 'restore incorrect [sign.curve]' '
	config_sign_curve_ca | sed /require-ca/d >>conf.d/sign.toml
'

test_expect_success 'sign fails with incorrect [sign.curve] config' '
	test_must_fail ${sign} </dev/null 2>xbadconf.err &&
	grep -q "must be set" xbadconf.err
'

test_expect_success 'restore [sign.curve] config with wrong cert-path' '
	config_sign >conf.d/sign.toml &&
	config_sign_curve_ca | sed s%/u%/noexist% >>conf.d/sign.toml
'

test_expect_success 'sign fails with missing cert' '
	test_must_fail ${sign} </dev/null 2>xnocert.err &&
	grep -q "load" xnocert.err
'

test_expect_success 'restore [sign.curve] config' '
	config_sign >conf.d/sign.toml &&
	config_sign_curve_ca >>conf.d/sign.toml
'

test_expect_success 'drop [ca] config' '
	cp /dev/null conf.d/ca.toml
'

test_expect_success 'verify fails with missing [ca] config' '
	${sign} </dev/null >noca.out &&
	test_must_fail ${verify} <noca.out 2>noca.err &&
	grep -q "config missing" noca.err
'

test_expect_success 'restore incorrect [ca]' '
	config_ca | sed /domain/d >conf.d/ca.toml
'

test_expect_success 'verify fails with incorrect [ca] config' '
	${sign} </dev/null >badca.out &&
	test_must_fail ${verify} <badca.out 2>badca.err &&
	grep -q "must be set" badca.err
'

test_expect_success 'set up test password file' '
	testuid=$(id -u) &&
	mkdir -p testuser &&
	cat >passwd <<-EOT
	testuser:x:${testuid}:42:Test User:${SHARNESS_TRASH_DIRECTORY}/testuser:/bin/false
	EOT
'

test_expect_success 'LD_PRELOAD getpwuid(3) works' '
	testuid=$(id -u) &&
	testhome=$(TEST_PASSWD_FILE=${SHARNESS_TRASH_DIRECTORY}/passwd \
		LD_PRELOAD=${prelib} ${uidlookup} ${testuid}) &&
	test "${testhome}" = "${SHARNESS_TRASH_DIRECTORY}/testuser"

'

test_expect_success 'configure for no CA' '
	cp /dev/null conf.d/ca.toml &&
	config_sign >conf.d/sign.toml &&
	config_sign_curve_noca >>conf.d/sign.toml
'

test_expect_success 'generate user signing cert with no CA signature' '
	mkdir -p testuser/.flux/curve &&
	${keygen} testuser/.flux/curve/sig
'

test_expect_success 'sign/verify zero length payload using unsigned cert' '
	TEST_PASSWD_FILE=${SHARNESS_TRASH_DIRECTORY}/passwd \
		LD_PRELOAD=${prelib} ${sign} </dev/null >znoca.out &&
	TEST_PASSWD_FILE=${SHARNESS_TRASH_DIRECTORY}/passwd \
		LD_PRELOAD=${prelib} ${verify} <znoca.out
'

test_expect_success 'verify fails after home cert is changed' '
	${keygen} testuser/.flux/curve/sig &&
	! TEST_PASSWD_FILE=${SHARNESS_TRASH_DIRECTORY}/passwd \
	  LD_PRELOAD=${prelib} ${verify} <znoca.out 2>xznoca.err &&
	grep -q "cert verification failed" xznoca.err
'

test_expect_success 'verify fails after home cert is removed' '
	rm testuser/.flux/curve/sig testuser/.flux/curve/sig.pub &&
	! TEST_PASSWD_FILE=${SHARNESS_TRASH_DIRECTORY}/passwd \
	  LD_PRELOAD=${prelib} ${verify} <znoca.out 2>yznoca.err &&
	grep -q "error loading cert" yznoca.err
'

test_expect_success 'sign fails if no password file entry' '
	! TEST_PASSWD_FILE=/dev/null LD_PRELOAD=${prelib} ${sign} </dev/null
'

test_done
