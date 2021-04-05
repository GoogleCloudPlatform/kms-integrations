load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(default_visibility = ["//kmsp11:__subpackages__"])

go_test(
    name = "benchmark_test",
    srcs = ["benchmark_test.go"],
    args = ["-test.bench=."],
    data = ["//kmsp11/main:libkmsp11.so"],
    tags = [
        # This test is manual because of the expected KMS traffic spike and its
        # longer runtime which doesn't add too much value to regular builds.
        "manual",
    ],
    deps = [
        "@com_github_miekg_pkcs11//:go_default_library",
        "@go_googleapis//google/cloud/kms/v1:kms_go_proto",
        "@io_bazel_rules_go//go/tools/bazel:go_default_library",
    ],
)
