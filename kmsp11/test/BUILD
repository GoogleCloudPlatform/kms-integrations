load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

package(default_visibility = ["//kmsp11:__subpackages__"])

cc_library(
    name = "matchers",
    testonly = 1,
    hdrs = ["matchers.h"],
    deps = [
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "matchers_test",
    size = "small",
    srcs = ["matchers_test.cc"],
    deps = [
        ":matchers",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest_main",
    ],
)
