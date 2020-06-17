load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

package(default_visibility = ["//kmsp11:__subpackages__"])

cc_library(
    name = "crypter_interfaces",
    hdrs = ["crypter_interfaces.h"],
    deps = [
        "//kmsp11:cryptoki_headers",
        "//kmsp11:object",
        "//kmsp11/util:kms_client",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "crypter_ops",
    srcs = ["crypter_ops.cc"],
    hdrs = ["crypter_ops.h"],
    deps = [
        ":crypter_interfaces",
        ":ecdsa",
        ":rsaes_oaep",
        "//kmsp11/util:errors",
    ],
)

cc_test(
    name = "crypter_ops_test",
    size = "small",
    srcs = ["crypter_ops_test.cc"],
    deps = [
        ":crypter_ops",
        "//kmsp11/test",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "ecdsa",
    srcs = ["ecdsa.cc"],
    hdrs = ["ecdsa.h"],
    deps = [
        ":crypter_interfaces",
        ":kms_signer",
        ":preconditions",
        "//kmsp11:cryptoki_headers",
        "//kmsp11/util:cleanup",
        "//kmsp11/util:crypto_utils",
        "//kmsp11/util:kms_client",
        "//kmsp11/util:status_macros",
        "//kmsp11/util:status_or",
        "//kmsp11/util:string_utils",
    ],
)

cc_test(
    name = "ecdsa_test",
    size = "small",
    srcs = ["ecdsa_test.cc"],
    deps = [
        ":ecdsa",
        "//kmsp11/test",
        "//kmsp11/test/fakekms/cpp:fakekms",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "find",
    hdrs = ["find.h"],
    deps = [
        "//kmsp11:cryptoki_headers",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "kms_signer",
    srcs = ["kms_signer.cc"],
    hdrs = ["kms_signer.h"],
    deps = [
        ":crypter_interfaces",
        "//kmsp11:cryptoki_headers",
        "//kmsp11/util:crypto_utils",
        "//kmsp11/util:kms_client",
        "//kmsp11/util:status_macros",
        "//kmsp11/util:status_or",
    ],
)

cc_library(
    name = "operation",
    hdrs = ["operation.h"],
    deps = [
        ":crypter_ops",
        ":find",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_library(
    name = "preconditions",
    srcs = ["preconditions.cc"],
    hdrs = ["preconditions.h"],
    deps = [
        "//kmsp11:cryptoki_headers",
        "//kmsp11:object",
        "@com_google_absl//absl/status",
    ],
)

cc_test(
    name = "preconditions_test",
    size = "small",
    srcs = ["preconditions_test.cc"],
    deps = [
        ":preconditions",
        "//kmsp11/test",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "rsaes_oaep",
    srcs = ["rsaes_oaep.cc"],
    hdrs = ["rsaes_oaep.h"],
    deps = [
        ":crypter_interfaces",
        ":preconditions",
        "//kmsp11:cryptoki_headers",
        "//kmsp11/util:cleanup",
        "//kmsp11/util:crypto_utils",
        "//kmsp11/util:kms_client",
        "//kmsp11/util:status_macros",
        "//kmsp11/util:status_or",
        "//kmsp11/util:string_utils",
    ],
)

cc_test(
    name = "rsaes_oaep_test",
    size = "small",
    srcs = ["rsaes_oaep_test.cc"],
    deps = [
        ":rsaes_oaep",
        "//kmsp11/test",
        "//kmsp11/test/fakekms/cpp:fakekms",
        "@com_google_googletest//:gtest_main",
    ],
)
