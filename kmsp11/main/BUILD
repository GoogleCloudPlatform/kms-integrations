load(":function_def_template.bzl", "function_def_template")
load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library", "go_test")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(default_visibility = ["//kmsp11:__subpackages__"])

# Note that main.cc is included in this translation unit because
# C_GetFunctionList must return pointers to those functions.
cc_library(
    name = "bridge",
    srcs = [
        "bridge.cc",
        "main.cc",
        "unsupported.cc",
    ],
    hdrs = [
        "bridge.h",
        "function_list.h",
    ],
    linkstatic = 1,
    deps = [
        "//kmsp11:cryptoki_headers",
        "//kmsp11:mechanism",
        "//kmsp11:provider",
        "//kmsp11/config",
        "//kmsp11/util:cleanup",
        "//kmsp11/util:errors",
        "//kmsp11/util:logging",
        "@com_google_absl//absl/status",
    ],
    alwayslink = 1,
)

cc_test(
    name = "bridge_test",
    size = "small",
    srcs = ["bridge_test.cc"],
    deps = [
        ":bridge",
        "//kmsp11/test",
        "//kmsp11/test/fakekms/cpp:fakekms",
        "//kmsp11/util:cleanup",
        "//kmsp11/util:platform",
        "@com_google_googletest//:gtest_main",
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
        "@org_golang_google_protobuf//testing/protocmp:go_default_library",
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
    name = "function_list",
    src = "function_list.h.template",
    out = "function_list.h",
)

cc_binary(
    name = "libkmsp11.so",
    linkopts = select({
        "//:linux": [
            # Make all symbols hidden, except those that are specifially exported.
            "-Wl,--version-script,$(location :linux_exports.lds)",
            # Disallow undefined symbols in object files.
            "-z defs",
            # Link statically with libstdc++ and libgcc
            "-static-libstdc++",
            "-static-libgcc",
        ],
        "//:macos": [
            # Make all symbols hidden, except those that are specifially exported.
            "-Wl,-exported_symbols_list,$(location :macos_exports.lds)",
        ],
        "//conditions:default": [],
    }),
    linkshared = 1,
    visibility = ["//visibility:public"],
    win_def_file = select({
        "//:windows": ":win_exports.def",
        "//conditions:default": None,
    }),
    deps = [":bridge"] +
           select({
               "//:linux": [":linux_exports.lds"],
               "//:macos": [":macos_exports.lds"],
               "//conditions:default": [],
           }),
)

function_def_template(
    name = "linux_exports",
    src = "linux_exports.lds.template",
    out = "linux_exports.lds",
)

function_def_template(
    name = "macos_exports",
    src = "macos_exports.lds.template",
    out = "macos_exports.lds",
)

function_def_template(
    name = "main_cc",
    src = "main.cc.template",
    out = "main.cc",
)

function_def_template(
    name = "win_exports",
    src = "win_exports.def.template",
    out = "win_exports.def",
)
