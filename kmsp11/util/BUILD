load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library", "cc_test")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(default_visibility = ["//kmsp11:__subpackages__"])

cc_library(
    name = "cleanup",
    hdrs = ["cleanup.h"],
)

cc_test(
    name = "cleanup_test",
    srcs = ["cleanup_test.cc"],
    deps = [
        ":cleanup",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "errors",
    srcs = ["errors.cc"],
    hdrs = ["errors.h"],
    deps = [
        ":source_location",
        ":status_utils",
        "@com_github_google_glog//:glog",
    ],
)

cc_test(
    name = "errors_test",
    size = "small",
    srcs = ["errors_test.cc"],
    deps = [
        ":errors",
        "//kmsp11/test:matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "platform",
    srcs = select({
        "//:windows": ["platform_win.cc"],
        "//conditions:default": ["platform_posix.cc"],
    }),
    hdrs = ["platform.h"],
)

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

cc_proto_library(
    name = "status_details_cc_proto",
    deps = [":status_details_proto"],
)

proto_library(
    name = "status_details_proto",
    srcs = ["status_details.proto"],
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
    srcs = ["status_utils.cc"],
    hdrs = ["status_utils.h"],
    deps = [
        ":status_details_cc_proto",
        ":status_or",
        "//kmsp11:cryptoki_headers",
        "@com_github_google_glog//:glog",
        "@com_google_absl//absl/status",
    ],
)

cc_test(
    name = "status_utils_test",
    size = "small",
    srcs = ["status_utils_test.cc"],
    deps = [
        ":status_utils",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "string_utils",
    srcs = ["string_utils.cc"],
    hdrs = ["string_utils.h"],
    deps = [
        ":errors",
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
