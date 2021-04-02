load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

package(default_visibility = ["//kmsp11:__subpackages__"])

exports_files(["function_defs.textproto"])

go_proto_library(
    name = "function_def_go_proto",
    importpath = "kmsp11",
    proto = ":function_def_proto",
)

proto_library(
    name = "function_def_proto",
    srcs = ["function_def.proto"],
)
