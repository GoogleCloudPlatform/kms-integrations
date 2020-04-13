load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

package(default_visibility = ["//kmsp11:__subpackages__"])

cc_library(
    name = "source_location",
    hdrs = ["source_location.h"],
    deps = [
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "source_location_test",
    size = "small",
    srcs = ["source_location_test.cc"],
    deps = [
        ":source_location",
        "//kmsp11/test:matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "status_macros",
    hdrs = ["status_macros.h"],
    deps = [
        ":status_or",
        "@com_google_absl//absl/status",
    ],
)

cc_test(
    name = "status_macros_test",
    size = "small",
    srcs = ["status_macros_test.cc"],
    deps = [
        ":status_macros",
        ":status_or",
        "//kmsp11/test",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "status_or",
    hdrs = ["status_or.h"],
    deps = [
        "@com_github_google_glog//:glog",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_test(
    name = "status_or_test",
    size = "small",
    srcs = ["status_or_test.cc"],
    deps = [
        ":status_or",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "status_utils",
    hdrs = ["status_utils.h"],
    deps = [
        ":status_or",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "string_utils",
    srcs = ["string_utils.cc"],
    hdrs = ["string_utils.h"],
    deps = [
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "string_utils_test",
    size = "small",
    srcs = ["string_utils_test.cc"],
    deps = [
        ":string_utils",
        "//kmsp11/test",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest_main",
    ],
)
