workspace(name = "com_google_kmstools")

# Direct Dependencies
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

http_archive(
    name = "bazel_gazelle",  # v0.20.0 / 2020-02-06
    sha256 = "d8c45ee70ec39a57e7a05e5027c32b1576cc7f16d9dd37135b0eddde45cf1b10",
    urls = [
        "https://storage.googleapis.com/bazel-mirror/github.com/bazelbuild/bazel-gazelle/releases/download/v0.20.0/bazel-gazelle-v0.20.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.20.0/bazel-gazelle-v0.20.0.tar.gz",
    ],
)

http_archive(
    name = "boringssl",  # 2020-05-20
    # Use github mirror instead of https://boringssl.googlesource.com/boringssl
    # to obtain a boringssl archive with consistent sha256
    sha256 = "3909329105e28cfeedcd8028865c92f1081ae2524a0ad6c09eba5d91d9ae3869",
    strip_prefix = "boringssl-3ab047a8e377083a9b38dc908fe1612d5743a021",
    url = "https://github.com/google/boringssl/archive/3ab047a8e377083a9b38dc908fe1612d5743a021.tar.gz",
)

http_archive(
    name = "com_github_gflags_gflags",  # 2020-03-18
    sha256 = "68e26a487038a842da3ef2ddd1f886dad656e9efaf1a3d49e87d1d3a9fa3a8eb",
    strip_prefix = "gflags-addd749114fab4f24b7ea1e0f2f837584389e52c",
    url = "https://github.com/gflags/gflags/archive/addd749114fab4f24b7ea1e0f2f837584389e52c.tar.gz",
)

http_archive(
    name = "com_github_google_glog",  # 2020-02-16
    sha256 = "6fc352c434018b11ad312cd3b56be3597b4c6b88480f7bd4e18b3a3b2cf961aa",
    strip_prefix = "glog-3ba8976592274bc1f907c402ce22558011d6fc5e",
    url = "https://github.com/google/glog/archive/3ba8976592274bc1f907c402ce22558011d6fc5e.tar.gz",
)

http_archive(
    name = "com_github_grpc_grpc",  # v1.29.1 / 2020-05-20
    sha256 = "bda7b52bab00592c115d5c2757ca729b665ed39cdf048541bf8aab212464c5a0",
    strip_prefix = "grpc-7d89dbb311f049b43bda7bbf6f7d7bf1b4c24419",
    urls = [
        "https://github.com/grpc/grpc/archive/7d89dbb311f049b43bda7bbf6f7d7bf1b4c24419.tar.gz",
    ],
)

http_archive(
    name = "com_github_jbeder_yaml_cpp",  # 2020-04-29
    sha256 = "736326d88059b5ebe77cb1d3825ade55c8708898817e067a05931444a7843faa",
    strip_prefix = "yaml-cpp-9fb51534877d16597cfd94c18890d87af0879d65",
    url = "https://github.com/jbeder/yaml-cpp/archive/9fb51534877d16597cfd94c18890d87af0879d65.tar.gz",
)

http_archive(
    name = "com_google_absl",  # 2020-04-07
    sha256 = "2ad95ee8fe9ee5aef55d8a9b59dfbd9c66056364a98dc3076ff3b32698b7bbe8",
    strip_prefix = "abseil-cpp-1112609635037a32435de7aa70a9188dcb591458",
    url = "https://github.com/abseil/abseil-cpp/archive/1112609635037a32435de7aa70a9188dcb591458.zip",
)

http_archive(
    name = "com_github_googleapis_google_cloud_cpp",  # 2020-05-26
    sha256 = "34caa64a89786248356c8289f4cdb7fd638fbcebf67cb80c02e3f999555fc9d1",
    strip_prefix = "google-cloud-cpp-56c57f2a4547cf57b614913015359bd33b4b5fa6",
    url = "https://github.com/googleapis/google-cloud-cpp/archive/56c57f2a4547cf57b614913015359bd33b4b5fa6.tar.gz",
)

http_archive(
    name = "com_google_googletest",  # 2020-04-03
    sha256 = "363089f62b375e6a73b7149015e7fe92e50d124ab4e95ba062774c496d96f2fc",
    strip_prefix = "googletest-e3f0319d89f4cbf32993de595d984183b1a9fc57",
    url = "https://github.com/google/googletest/archive/e3f0319d89f4cbf32993de595d984183b1a9fc57.zip",
)

http_archive(
    name = "com_google_protobuf",  # v3.11.4 / 2020-02-14
    sha256 = "c5fd8f99f0d30c6f9f050bf008e021ccc70d7645ac1f64679c6038e07583b2f3",
    strip_prefix = "protobuf-d0bfd5221182da1a7cc280f3337b5e41a89539cf",
    url = "https://github.com/protocolbuffers/protobuf/archive/d0bfd5221182da1a7cc280f3337b5e41a89539cf.zip",
)

http_archive(
    name = "io_bazel_rules_go",  # v0.23.0 / 2020-05-13
    sha256 = "6a68e269802911fa419abb940c850734086869d7fe9bc8e12aaf60a09641c818",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.23.0/rules_go-v0.23.0.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.23.0/rules_go-v0.23.0.tar.gz",
    ],
)

http_file(
    name = "pkcs11_h_v240",  # 2016-05-13
    downloaded_file_path = "pkcs11.h",
    sha256 = "8bb7aa1aeaa328b6a39913070d6f3d2bdeb9f2c92baf27f714fbb4cbefdf4054",
    urls = ["http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11.h"],
)

http_file(
    name = "pkcs11f_h_v240",  # 2016-05-13
    downloaded_file_path = "pkcs11f.h",
    sha256 = "a85adad038bfc9dad9c71377f3ed3b049ba2ac9b3f37198a372f211d210c6057",
    urls = ["http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11f.h"],
)

http_file(
    name = "pkcs11t_h_v240",  # 2016-05-13
    downloaded_file_path = "pkcs11t.h",
    sha256 = "5b58736b6d23f12b4d9492cd24b06b9d11056c3153afc4e89b1fe564749e71a2",
    urls = ["http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11t.h"],
)

# Transitive Dependencies

## Google Cloud CPP
load("@com_github_googleapis_google_cloud_cpp//bazel:google_cloud_cpp_deps.bzl", "google_cloud_cpp_deps")

google_cloud_cpp_deps()

load("@com_google_googleapis//:repository_rules.bzl", "switched_rules_by_language")

switched_rules_by_language(
    name = "com_google_googleapis_imports",
    cc = True,  # C++ support is only "Partially implemented", roll our own.
    grpc = True,
)

# gRPC

load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

grpc_deps()

# Call the workspace dependency functions defined, but not invoked, in grpc_deps.bzl.
load("@upb//bazel:workspace_deps.bzl", "upb_deps")

upb_deps()

load("@build_bazel_rules_apple//apple:repositories.bzl", "apple_rules_dependencies")

apple_rules_dependencies()

load("@build_bazel_apple_support//lib:repositories.bzl", "apple_support_dependencies")

apple_support_dependencies()

## Golang
load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

go_register_toolchains()

## Protobuf
load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

## Gazelle (go + bazel)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")

gazelle_dependencies()

load("//:go.bzl", "go_repositories")

# gazelle:repository_macro go.bzl%go_repositories
go_repositories()
