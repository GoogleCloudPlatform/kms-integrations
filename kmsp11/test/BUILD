load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

package(default_visibility = ["//kmsp11:__subpackages__"])

cc_library(
    name = "test",
    testonly = 1,
    deps = [
        ":matchers",
        ":test_status_macros",
    ],
)

cc_library(
    name = "matchers",
    testonly = 1,
    hdrs = ["matchers.h"],
    deps = [
        "//kmsp11/util:status_or",
        "//kmsp11/util:status_utils",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_test(
    name = "matchers_test",
    size = "small",
    srcs = ["matchers_test.cc"],
    deps = [
        ":matchers",
        "//kmsp11:cryptoki_headers",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "test_status_macros",
    testonly = 1,
    hdrs = ["test_status_macros.h"],
    deps = [
        ":matchers",
        "//kmsp11/util:status_macros",
        "//kmsp11/util:status_or",
        "//kmsp11/util:status_utils",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "test_status_macros_test",
    size = "small",
    srcs = ["test_status_macros_test.cc"],
    deps = [
        ":test_status_macros",
        "@com_google_googletest//:gtest_main",
    ],
)
