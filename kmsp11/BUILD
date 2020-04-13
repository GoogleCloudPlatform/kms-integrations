load("@rules_cc//cc:defs.bzl", "cc_library")

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
