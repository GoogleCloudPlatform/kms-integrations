load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

package(default_visibility = ["//kmsp11:__subpackages__"])

cc_library(
    name = "find",
    hdrs = ["find.h"],
    deps = [
        "//kmsp11:cryptoki_headers",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "operation",
    hdrs = ["operation.h"],
    deps = [
        ":find",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_library(
    name = "preconditions",
    srcs = ["preconditions.cc"],
    hdrs = ["preconditions.h"],
    deps = [
        "//kmsp11:cryptoki_headers",
        "//kmsp11:object",
        "@com_google_absl//absl/status",
    ],
)

cc_test(
    name = "preconditions_test",
    size = "small",
    srcs = ["preconditions_test.cc"],
    deps = [
        ":preconditions",
        "//kmsp11/test",
        "@com_google_googletest//:gtest_main",
    ],
)
