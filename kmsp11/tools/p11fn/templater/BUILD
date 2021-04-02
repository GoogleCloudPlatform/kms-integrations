load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
    name = "templater",
    srcs = ["templater.go"],
    visibility = ["//kmsp11:__subpackages__"],
    deps = [
        "//kmsp11/tools/p11fn:function_def_go_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
    ],
)
