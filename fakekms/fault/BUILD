load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")
load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")

package(default_visibility = ["//:__subpackages__"])

go_library(
    name = "fault",
    srcs = ["fault.go"],
    importpath = "cloud.google.com/kms/oss/fakekms/fault",
    deps = [
        ":fault_go_proto",
        "@org_golang_google_grpc//:go_default_library",
        "@org_golang_google_grpc//codes:go_default_library",
        "@org_golang_google_grpc//status:go_default_library",
        "@org_golang_google_protobuf//types/known/durationpb:go_default_library",
        "@org_golang_google_protobuf//types/known/emptypb:go_default_library",
    ],
)

go_test(
    name = "fault_test",
    srcs = ["fault_test.go"],
    embed = [":fault"],
    deps = [
        ":fault_go_proto",
        ":math_go_proto",
        "@go_googleapis//google/rpc:status_go_proto",
        "@org_golang_google_grpc//test/bufconn:go_default_library",
    ],
)

go_proto_library(
    name = "fault_go_proto",
    compilers = ["@io_bazel_rules_go//proto:go_grpc"],
    importpath = "cloud.google.com/kms/oss/fakekms/fault/faultpb",
    proto = ":fault_proto",
    deps = ["@go_googleapis//google/rpc:status_go_proto"],
)

proto_library(
    name = "fault_proto",
    srcs = ["fault.proto"],
    deps = [
        "@com_google_googleapis//google/rpc:status_proto",
        "@com_google_protobuf//:duration_proto",
        "@com_google_protobuf//:empty_proto",
    ],
)

proto_library(
    name = "math_proto",
    testonly = True,
    srcs = ["math.proto"],
)

go_proto_library(
    name = "math_go_proto",
    testonly = True,
    compilers = ["@io_bazel_rules_go//proto:go_grpc"],
    importpath = "cloud.google.com/kms/oss/fakekms/fault/mathpb",
    proto = ":math_proto",
)
