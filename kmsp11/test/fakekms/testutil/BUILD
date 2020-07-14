load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(default_visibility = ["//kmsp11/test/fakekms:__subpackages__"])

go_library(
    name = "testutil",
    testonly = 1,
    srcs = ["testutil.go"],
    importpath = "oss-tools/kmsp11/test/fakekms/testutil",
    deps = [
        "@com_github_golang_protobuf//ptypes:go_default_library_gen",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_google_uuid//:go_default_library",
        "@io_bazel_rules_go//proto/wkt:timestamp_go_proto",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_google_protobuf//testing/protocmp:go_default_library",
    ],
)

go_test(
    name = "testutil_test",
    size = "small",
    srcs = ["testutil_test.go"],
    embed = [":testutil"],
)
