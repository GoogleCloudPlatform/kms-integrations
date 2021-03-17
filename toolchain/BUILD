load(":llvm_toolchain.bzl", "llvm_cc_toolchain")
load("@bazel_skylib//rules:common_settings.bzl", "string_flag")
load("@rules_cc//cc:defs.bzl", "cc_toolchain_suite")

package(default_visibility = ["//visibility:public"])

string_flag(
    name = "llvm_root",
    build_setting_default = "/opt/llvm",
)

string_flag(
    name = "llvm_version",
    build_setting_default = "11.0.0",
)

llvm_cc_toolchain(
    name = "llvm_toolchain_linux_amd64",
    cpu = "k8",
)

cc_toolchain_suite(
    name = "llvm_suite",
    toolchains = {
        "k8": "llvm_toolchain_linux_amd64",
    },
    tags = ["manual"],
)
