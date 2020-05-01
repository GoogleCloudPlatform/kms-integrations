load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

package(default_visibility = ["//kmsp11:__subpackages__"])

genrule(
    name = "cryptoki_raw_header_files",
    srcs = [
        "@pkcs11_h_v240//file:pkcs11.h",
        "@pkcs11f_h_v240//file:pkcs11f.h",
        "@pkcs11t_h_v240//file:pkcs11t.h",
    ],
    outs = [
        "pkcs11.h",
        "pkcs11f.h",
        "pkcs11t.h",
    ],
    cmd = "cp $(SRCS) $(@D)",
)

cc_library(
    name = "cryptoki_raw_headers",
    hdrs = [":cryptoki_raw_header_files"],
    include_prefix = "",
)

cc_library(
    name = "cryptoki_headers",
    hdrs = ["cryptoki.h"],
    deps = [":cryptoki_raw_headers"],
)

cc_library(
    name = "provider",
    srcs = ["provider.cc"],
    hdrs = ["provider.h"],
    deps = [
        ":cryptoki_headers",
        "//kmsp11/config:config_cc_proto",
        "//kmsp11/util:status_macros",
        "//kmsp11/util:status_or",
        "//kmsp11/util:string_utils",
    ],
)

cc_test(
    name = "provider_test",
    size = "small",
    srcs = ["provider_test.cc"],
    deps = [
        ":provider",
        "//kmsp11/test",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "token",
    srcs = ["token.cc"],
    hdrs = ["token.h"],
    deps = [
        ":cryptoki_headers",
        "//kmsp11/config:config_cc_proto",
        "//kmsp11/util:status_macros",
        "//kmsp11/util:status_or",
        "//kmsp11/util:string_utils",
    ],
)

cc_test(
    name = "token_test",
    size = "small",
    srcs = ["token_test.cc"],
    deps = [
        ":token",
        "//kmsp11/test",
        "@com_google_googletest//:gtest_main",
    ],
)
