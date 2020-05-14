load("@io_bazel_rules_go//go:def.bzl", "go_test")

go_test(
    name = "contract_test",
    srcs = glob(["*_test.go"]),
    deps = [
        "//kmsp11/test/fakekms",
        "//kmsp11/test/fakekms/testutil",
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
    ],
)
