load(":function_def_template.bzl", "function_def_template")
load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library", "go_test")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(default_visibility = ["//kmsp11:__subpackages__"])

# Note that main.cc is included in this translation unit because
# C_GetFunctionList must return pointers to those functions.
cc_library(
    name = "bridge",
    srcs = [
        "main.cc",
        "unsupported.cc",
    ],
    hdrs = ["bridge.h"],
    deps = [
        "//kmsp11:cryptoki_headers",
        "//kmsp11/util:errors",
        "@com_google_absl//absl/status",
    ],
)

function_def_template(
    name = "bridge_h",
    src = "bridge.h.template",
    out = "bridge.h",
)

go_binary(
    name = "function_def_builder",
    srcs = ["function_def_builder.go"],
    deps = [
        ":function_def_scanner",
        "@com_github_golang_protobuf//proto:go_default_library",
    ],
)

go_proto_library(
    name = "function_def_go_proto",
    importpath = "kmsp11",
    proto = ":function_def_proto",
)

proto_library(
    name = "function_def_proto",
    srcs = ["function_def.proto"],
)

go_library(
    name = "function_def_scanner",
    srcs = ["function_def_scanner.go"],
    embed = [":function_def_go_proto"],
    importpath = "kmsp11",
)

go_test(
    name = "function_def_scanner_test",
    size = "small",
    srcs = ["function_def_scanner_test.go"],
    embed = [":function_def_scanner"],
    importpath = "kmsp11",
    deps = [
        "@com_github_golang_protobuf//proto:go_default_library",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

go_binary(
    name = "function_def_templater",
    srcs = ["function_def_templater.go"],
    deps = [
        ":function_def_go_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
    ],
)

genrule(
    name = "function_defs",
    srcs = ["@pkcs11f_h_v240//file:pkcs11f.h"],
    outs = ["function_defs.textproto"],
    cmd = """
    \"$(location :function_def_builder)\" \
        --pkcs11f_path \"$(SRCS)\" > \"$(@)\"""",
    tools = [":function_def_builder"],
)

function_def_template(
    name = "main_cc",
    src = "main.cc.template",
    out = "main.cc",
)
