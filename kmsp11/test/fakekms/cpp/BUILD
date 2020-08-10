load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

package(default_visibility = ["//kmsp11:__subpackages__"])

cc_library(
    name = "fakekms",
    testonly = 1,
    srcs = select({
        "//:windows": ["fakekms_win.cc"],
        "//conditions:default": ["fakekms_posix.cc"],
    }),
    hdrs = ["fakekms.h"],
    data = ["//kmsp11/test/fakekms/main:fakekms"],
    deps = [
        "//kmsp11/test",
        "//kmsp11/util:cleanup",
        "//kmsp11/util:kms_v1",
        "//kmsp11/util:status_macros",
        "//kmsp11/util:status_or",
        "@com_github_google_glog//:glog",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/strings",
    ],
    defines = select({
        # https://www.freebsd.org/cgi/man.cgi?query=getline&manpath=FreeBSD+11.4-RELEASE
        "//:freebsd": ["_WITH_GETLINE"],
        "//conditions:default": [],
    })
)

cc_test(
    name = "fakekms_test",
    size = "small",
    srcs = ["fakekms_test.cc"],
    data = [
        "//kmsp11/test/fakekms/main:fakekms",
    ],
    deps = [
        ":fakekms",
        "//kmsp11/test",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googletest//:gtest_main",
    ],
)
