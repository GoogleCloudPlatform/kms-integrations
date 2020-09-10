load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

package(default_visibility = ["//kmsp11:__subpackages__"])

cc_library(
    name = "algorithm_details",
    srcs = ["algorithm_details.cc"],
    hdrs = ["algorithm_details.h"],
    deps = [
        ":cryptoki_headers",
        "//kmsp11/util:errors",
        "//kmsp11/util:kms_v1",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_test(
    name = "algorithm_details_test",
    size = "small",
    srcs = ["algorithm_details_test.cc"],
    deps = [
        ":algorithm_details",
        "//kmsp11/test",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "attribute_map",
    srcs = ["attribute_map.cc"],
    hdrs = ["attribute_map.h"],
    deps = [
        ":cryptoki_headers",
        "//kmsp11/util:errors",
        "//kmsp11/util:string_utils",
        "@boringssl//:crypto",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_test(
    name = "attribute_map_test",
    size = "small",
    srcs = ["attribute_map_test.cc"],
    deps = [
        ":attribute_map",
        "//kmsp11/test",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "cert_authority",
    srcs = ["cert_authority.cc"],
    hdrs = ["cert_authority.h"],
    deps = [
        "//kmsp11/util:crypto_utils",
        "//kmsp11/util:errors",
        "//kmsp11/util:kms_client",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "cert_authority_test",
    size = "small",
    srcs = ["cert_authority_test.cc"],
    deps = [
        ":cert_authority",
        "//kmsp11/test",
        "@com_google_googletest//:gtest_main",
    ],
)

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
    name = "mechanism",
    srcs = ["mechanism.cc"],
    hdrs = ["mechanism.h"],
    deps = [
        ":cryptoki_headers",
        "//kmsp11/util:errors",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_test(
    name = "mechanism_test",
    size = "small",
    srcs = ["mechanism_test.cc"],
    deps = [
        ":mechanism",
        "//kmsp11/test",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "object",
    srcs = ["object.cc"],
    hdrs = ["object.h"],
    deps = [
        ":algorithm_details",
        ":attribute_map",
        ":cert_authority",
        ":cryptoki_headers",
        "//kmsp11/util:crypto_utils",
        "//kmsp11/util:kms_v1",
        "//kmsp11/util:status_macros",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "object_test",
    size = "small",
    srcs = ["object_test.cc"],
    deps = [
        ":object",
        "//kmsp11/test",
        "//kmsp11/util:crypto_utils",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "provider",
    srcs = ["provider.cc"],
    hdrs = ["provider.h"],
    deps = [
        ":cryptoki_headers",
        ":session",
        ":token",
        ":version",
        "//kmsp11/config:config_cc_proto",
        "//kmsp11/util:errors",
        "//kmsp11/util:handle_map",
        "//kmsp11/util:platform",
        "//kmsp11/util:status_macros",
        "//kmsp11/util:string_utils",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_test(
    name = "provider_test",
    size = "small",
    srcs = ["provider_test.cc"],
    deps = [
        ":provider",
        "//kmsp11/test",
        "//kmsp11/test/fakekms/cpp:fakekms",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "session",
    srcs = ["session.cc"],
    hdrs = ["session.h"],
    deps = [
        ":token",
        "//kmsp11/operation",
    ],
)

cc_test(
    name = "session_test",
    size = "small",
    srcs = ["session_test.cc"],
    deps = [
        ":session",
        "//kmsp11/test",
        "//kmsp11/test/fakekms/cpp:fakekms",
        "//kmsp11/util:crypto_utils",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "token",
    srcs = ["token.cc"],
    hdrs = ["token.h"],
    deps = [
        ":cryptoki_headers",
        ":object",
        "//kmsp11:algorithm_details",
        "//kmsp11/config:config_cc_proto",
        "//kmsp11/util:handle_map",
        "//kmsp11/util:kms_client",
        "//kmsp11/util:status_macros",
        "//kmsp11/util:string_utils",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/synchronization",
    ],
)

cc_test(
    name = "token_test",
    size = "small",
    srcs = ["token_test.cc"],
    deps = [
        ":token",
        "//kmsp11/test",
        "//kmsp11/test/fakekms/cpp:fakekms",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "version",
    hdrs = ["version.h"],
    deps = [":cryptoki_headers"],
)
