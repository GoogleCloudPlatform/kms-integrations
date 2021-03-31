load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library", "go_test")

package(default_visibility = ["//kmsp11:__subpackages__"])

go_test(
    name = "benchmark_test",
    srcs = ["benchmark_test.go"],
    data = ["//kmsp11/main:libkmsp11.so"],
    tags = [
        # This test is manual because of the expected KMS traffic spike and its
        # longer runtime which doesn't add too much value to regular builds.
        "manual",
    ],
    deps = [
        "@com_github_miekg_pkcs11//:go_default_library",
        "@io_bazel_rules_go//go/tools/bazel:go_default_library",
    ],
)
