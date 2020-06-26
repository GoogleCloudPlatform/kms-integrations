load("@rules_cc//cc:defs.bzl", "cc_binary")
load("@rules_java//java:defs.bzl", "java_library", "java_test")

java_library(
    name = "Environment",
    srcs = ["Environment.java"],
    data = [":libenv.so"],
    deps = [
        "@bazel_tools//tools/java/runfiles",
        "@maven//:com_google_guava_guava",
    ],
)

java_library(
    name = "JcaTestFixture",
    srcs = ["JcaTestFixture.java"],
    data = [
        "//kmsp11/main:libkmsp11.so",
        "@com_github_grpc_grpc//:etc/roots.pem",
    ],
    deps = [
        ":Environment",
        "//kmsp11/test/fakekms/java:FakeKms",
        "@bazel_tools//tools/java/runfiles",
        "@maven//:com_google_api_grpc_proto_google_cloud_kms_v1",
        "@maven//:com_google_cloud_google_cloud_kms",
    ],
)

cc_binary(
    name = "libenv.so",
    srcs = ["env.cc"],
    linkshared = 1,
    deps = [
        "//kmsp11/util:platform",
        "@bazel_tools//tools/jdk:jni",
    ],
)

java_test(
    name = "SignatureTest",
    srcs = ["SignatureTest.java"],
    test_class = "kmsp11.test.jca.SignatureTest",
    deps = [
        ":JcaTestFixture",
        "@maven//:com_google_api_grpc_proto_google_cloud_kms_v1",
        "@maven//:com_google_cloud_google_cloud_kms",
        "@maven//:junit_junit",
    ],
)
