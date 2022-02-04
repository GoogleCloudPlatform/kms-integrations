workspace(name = "com_google_kmstools")

# Direct Dependencies
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

http_archive(
    name = "bazel_gazelle",  # v0.24.0 / 2021-10-11
    sha256 = "de69a09dc70417580aabf20a28619bb3ef60d038470c7cf8442fafcf627c21cb",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
    ],
)

http_archive(
    name = "io_bazel_rules_go",  # v0.30.0 / 2022-01-24
    sha256 = "d6b2513456fe2229811da7eb67a444be7785f5323c6708b38d851d2b51e54d83",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.30.0/rules_go-v0.30.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.30.0/rules_go-v0.30.0.zip",
    ],
)

load("boringssl.bzl", "select_crypto_library")

select_crypto_library()

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
    name = "com_github_grpc_grpc",  # v1.36.4 / 2021-03-18
    sha256 = "89bab58f7bd36f2826b0bde92ea5668324642fe281d636dd18025354586cb764",
    strip_prefix = "grpc-3e53dbe8213137d2c731ecd4d88ebd2948941d75",
    url = "https://github.com/grpc/grpc/archive/3e53dbe8213137d2c731ecd4d88ebd2948941d75.tar.gz",
)

http_archive(
    name = "com_github_jbeder_yaml_cpp",  # v0.7.0 // 2021-07-10
    sha256 = "43e6a9fcb146ad871515f0d0873947e5d497a1c9c60c58cb102a97b47208b7c3",
    strip_prefix = "yaml-cpp-yaml-cpp-0.7.0",
    url = "https://github.com/jbeder/yaml-cpp/archive/yaml-cpp-0.7.0.tar.gz",
)

http_archive(
    name = "com_google_absl",  # 20211102.0 // 2021-11-02
    # Patch is upstreamed at cl/425532352; and should no longer be needed after
    # that makes it to OSS.
    patch_args = [
        "-E",
        "-p1",
    ],
    patches = ["//:third_party/abseil_freebsd_i386.patch"],
    sha256 = "dcf71b9cba8dc0ca9940c4b316a0c796be8fab42b070bb6b7cab62b48f0e66c4",
    strip_prefix = "abseil-cpp-20211102.0",
    url = "https://github.com/abseil/abseil-cpp/archive/20211102.0.tar.gz",
)

http_archive(
    name = "com_google_googletest",  # 2020-04-03
    sha256 = "363089f62b375e6a73b7149015e7fe92e50d124ab4e95ba062774c496d96f2fc",
    strip_prefix = "googletest-e3f0319d89f4cbf32993de595d984183b1a9fc57",
    url = "https://github.com/google/googletest/archive/e3f0319d89f4cbf32993de595d984183b1a9fc57.zip",
)

http_archive(
    name = "com_google_protobuf",  # v3.19.4 // 2022-01-2
    sha256 = "3bd7828aa5af4b13b99c191e8b1e884ebfa9ad371b0ce264605d347f135d2568",
    strip_prefix = "protobuf-3.19.4",
    url = "https://github.com/protocolbuffers/protobuf/archive/v3.19.4.tar.gz",
)

# In general it's best to keep this sync'd with the version used in rules_go,
# above. Otherwise, we're working with two versions of the same repo.
# https://github.com/bazelbuild/rules_go/blob/v0.30.0/go/private/repositories.bzl#L259
http_archive(
    name = "com_google_googleapis",  # 2022-01-24
    sha256 = "ad0a426b3cf0a8464c495627286c1cefdebefdabb96cc256aaeac9f501665cdd",
    strip_prefix = "googleapis-d12b615374583712e7832c914d1fbef8c507f10f",
    urls = [
        "https://mirror.bazel.build/github.com/googleapis/googleapis/archive/d12b615374583712e7832c914d1fbef8c507f10f.zip",
        "https://github.com/googleapis/googleapis/archive/d12b615374583712e7832c914d1fbef8c507f10f.zip",
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

http_archive(
    name = "rules_jvm_external",  # v4.2 // 2021-11-23
    sha256 = "2cd77de091e5376afaf9cc391c15f093ebd0105192373b334f0a855d89092ad5",
    strip_prefix = "rules_jvm_external-4.2",
    url = "https://github.com/bazelbuild/rules_jvm_external/archive/4.2.tar.gz",
)

http_archive(
    name = "rules_foreign_cc",  # 2021-03-18
    patch_args = [
        "-E",
        "-p1",
    ],
    patches = ["//:third_party/rules_foreign_cc.patch"],
    sha256 = "776d661daddf614b678abfb36f9624335fbad2d618afbf773759d421bcef49c5",
    strip_prefix = "rules_foreign_cc-d02390f1363cdd2ba5a7f7907a481503d483d569",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/d02390f1363cdd2ba5a7f7907a481503d483d569.tar.gz",
)

load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")

rules_foreign_cc_dependencies(register_built_tools = False)

# Transitive Dependencies

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

## Java

load("@rules_jvm_external//:defs.bzl", "maven_install")

maven_install(
    artifacts = [
        "com.google.cloud:google-cloud-kms:2.4.0",
        "com.google.guava:guava:31.0.1-jre",
        "junit:junit:4.13.2",
    ],
    fetch_sources = True,
    repositories = [
        "https://repo.maven.apache.org/maven2/",
    ],
)

## Golang
load("//:go.bzl", "go_repositories")

# gazelle:repository_macro go.bzl%go_repositories
go_repositories()

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

go_register_toolchains("1.17.6")

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")

gazelle_dependencies()

## Protobuf
load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()
