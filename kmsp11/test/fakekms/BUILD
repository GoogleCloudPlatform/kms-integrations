load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "fakekms",
    srcs = glob(
        ["*.go"],
        exclude = ["*_test.go"],
    ),
    importpath = "oss-tools/kmsp11/test/fakekms",
    visibility = ["//visibility:public"],
    deps = [
        "@com_github_golang_protobuf//proto:go_default_library",
        "@com_github_golang_protobuf//ptypes:go_default_library_gen",
        "@go_googleapis//google/cloud/kms/v1:kms_go_proto",
        "@org_golang_google_grpc//:go_default_library",
        "@org_golang_google_grpc//codes:go_default_library",
        "@org_golang_google_grpc//status:go_default_library",
        "@org_golang_google_protobuf//reflect/protoreflect:go_default_library",
    ],
)

go_test(
    name = "fakekms_test",
    srcs = glob(["*_test.go"]),
    embed = [":fakekms"],
    deps = [
        "@com_github_golang_protobuf//proto:go_default_library",
        "@go_googleapis//google/cloud/kms/v1:kms_go_proto",
        "@org_golang_google_grpc//codes:go_default_library",
        "@org_golang_google_grpc//status:go_default_library",
        "@org_golang_google_protobuf//reflect/protoreflect:go_default_library",
    ],
)
