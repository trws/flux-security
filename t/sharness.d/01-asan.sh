##
# Is flux-security built with --enable-sanitizers?
##
if ${SHARNESS_BUILD_DIRECTORY}/t/src/sanitizers-enabled; then
    test_set_prereq ASAN
else
    test_set_prereq NO_ASAN
fi
