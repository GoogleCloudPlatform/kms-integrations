load("@rules_cc//cc:defs.bzl", "cc_library")

package(default_visibility = ["//kmsp11:__subpackages__"])

cc_library(
    name = "bridge",
    srcs = [
        "unsupported.cc",
    ],
    deps = [
        "//kmsp11:cryptoki_headers",
        "//kmsp11/util:errors",
        "@com_google_absl//absl/status",
    ],
)
