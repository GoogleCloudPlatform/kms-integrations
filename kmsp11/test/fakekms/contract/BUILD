load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "contract_test_util",
    testonly = 1,
    srcs = ["util.go"],
    importpath = "contract",
    deps = [
        "@com_github_golang_protobuf//ptypes:go_default_library_gen",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_google_uuid//:go_default_library",
        "@io_bazel_rules_go//proto/wkt:timestamp_go_proto",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_google_protobuf//testing/protocmp:go_default_library",
    ],
)

go_test(
    name = "contract_test_util_test",
    size = "small",
    srcs = ["util_test.go"],
    embed = [":contract_test_util"],
)

go_test(
    name = "contract_test",
    size = "small",
    srcs = glob(
        ["*.go"],
        exclude = glob(["util*.go"]),
    ),
    embed = [":contract_test_util"],
    deps = [
        "//kmsp11/test/fakekms",
        "@com_github_golang_protobuf//ptypes:go_default_library_gen",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_google_uuid//:go_default_library",
        "@com_google_cloud_go//kms/apiv1:go_default_library",
        "@go_googleapis//google/cloud/kms/v1:kms_go_proto",
        "@io_bazel_rules_go//proto/wkt:field_mask_go_proto",
        "@org_golang_google_api//option:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
        "@org_golang_google_grpc//codes:go_default_library",
        "@org_golang_google_grpc//status:go_default_library",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_google_protobuf//reflect/protoreflect:go_default_library",
        "@org_golang_google_protobuf//testing/protocmp:go_default_library",
        "@org_golang_google_protobuf//types/known/durationpb:go_default_library",
        "@org_golang_google_protobuf//types/known/wrapperspb:go_default_library",
    ],
)
