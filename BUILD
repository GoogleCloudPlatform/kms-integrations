config_setting(
    name = "freebsd",
    constraint_values = ["@platforms//os:freebsd"],
)

config_setting(
    name = "linux",
    constraint_values = ["@platforms//os:linux"],
)

config_setting(
    name = "macos",
    constraint_values = ["@platforms//os:macos"],
)

config_setting(
    name = "windows",
    constraint_values = ["@platforms//os:windows"],
)

# A target to encompass tests that are tagged 'manual'
# but should be run for release builds.
test_suite(
    name = "release_tests",
    tags = ["manual"],
    tests = ["//kmsp11/main:binary_test"],
)
