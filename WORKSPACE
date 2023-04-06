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
    name = "io_bazel_rules_go",  # v0.33.0 / 2022-06-06
    # Patch HMAC and interoperable encryption into rules_go's copy of googleapis.
    patch_args = [
        "-E",
        "-p1",
    ],
    patches = ["//:third_party/rules_go.patch"],
    sha256 = "685052b498b6ddfe562ca7a97736741d87916fe536623afb7da2824c0211c369",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.33.0/rules_go-v0.33.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.33.0/rules_go-v0.33.0.zip",
    ],
)

load("boringssl.bzl", "select_crypto_library")

select_crypto_library()

load("//kmscng:cpdk.bzl", "cpdk")

cpdk(name = "cpdk")

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
    name = "com_github_grpc_grpc",  # v1.52.1 / 2023-02-15
    sha256 = "ec125d7fdb77ecc25b01050a0d5d32616594834d3fe163b016768e2ae42a2df6",
    strip_prefix = "grpc-1.52.1",
    url = "https://github.com/grpc/grpc/archive/v1.52.1.tar.gz",
)

http_archive(
    name = "com_github_jbeder_yaml_cpp",  # v0.7.0 // 2021-07-10
    sha256 = "43e6a9fcb146ad871515f0d0873947e5d497a1c9c60c58cb102a97b47208b7c3",
    strip_prefix = "yaml-cpp-yaml-cpp-0.7.0",
    url = "https://github.com/jbeder/yaml-cpp/archive/yaml-cpp-0.7.0.tar.gz",
)

http_archive(
    name = "com_google_absl",  # 2023-04-03
    sha256 = "ca1428b2593432f56c9a8db6d8e98ae926618d78a64b8bc2f6ebcc8fac49cada",
    strip_prefix = "abseil-cpp-c4127a721f498ad417b4db603e643822305cb11e",
    url = "https://github.com/abseil/abseil-cpp/archive/c4127a721f498ad417b4db603e643822305cb11e.tar.gz",
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
# https://github.com/bazelbuild/rules_go/blob/v0.33.0/go/private/repositories.bzl#L244
http_archive(
    name = "com_google_googleapis",  # 2022-06-05
    # Patch HMAC and interoperable encryption into googleapis.
    patch_args = [
        "-E",
        "-p1",
    ],
    patches = ["//:third_party/googleapis.patch"],
    sha256 = "9181bb36a1df4f397375ec5aa480db797b882073518801e3a20b0e46418f2f90",
    strip_prefix = "googleapis-530ca55953b470ab3b37dc9de37fcfa59410b741",
    urls = [
        "https://mirror.bazel.build/github.com/googleapis/googleapis/archive/530ca55953b470ab3b37dc9de37fcfa59410b741.zip",
        "https://github.com/googleapis/googleapis/archive/530ca55953b470ab3b37dc9de37fcfa59410b741.zip",
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

# TODO(b/234842124): drop gapic and java once the interoperable AES proto changes are released.
switched_rules_by_language(
    name = "com_google_googleapis_imports",
    cc = True,  # C++ support is only "Partially implemented", roll our own.
    gapic = True,
    grpc = True,
    java = True,
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

# rules_gapic also depends on rules_go, so it must come after our own dependency on rules_go.
_rules_gapic_version = "0.13.0"

_rules_gapic_sha256 = "1ebbd74b064697f4ff01d8f59764ba8431d52673f48f636be6b135b6da640b8e"

http_archive(
    name = "rules_gapic",
    sha256 = _rules_gapic_sha256,
    strip_prefix = "rules_gapic-%s" % _rules_gapic_version,
    urls = ["https://github.com/googleapis/rules_gapic/archive/v%s.tar.gz" % _rules_gapic_version],
)

load("@rules_gapic//:repositories.bzl", "rules_gapic_repositories")

rules_gapic_repositories()

## Java
# Begin: Googleapis Java dependencies
# This section is based off of the WORKSPACE file of googleapis:
# https://github.com/googleapis/googleapis/blob/master/WORKSPACE
load("@com_google_protobuf//:protobuf_deps.bzl", "PROTOBUF_MAVEN_ARTIFACTS")

# Starting in protobuf 3.19, protobuf project started to provide
# PROTOBUF_MAVEN_ARTIFACTS variable so that Bazel users can resolve their
# dependencies through maven_install.
# https://github.com/protocolbuffers/protobuf/issues/9132
RULES_JVM_EXTERNAL_TAG = "4.2"

RULES_JVM_EXTERNAL_SHA = "cd1a77b7b02e8e008439ca76fd34f5b07aecb8c752961f9640dea15e9e5ba1ca"

http_archive(
    name = "rules_jvm_external",
    sha256 = RULES_JVM_EXTERNAL_SHA,
    strip_prefix = "rules_jvm_external-%s" % RULES_JVM_EXTERNAL_TAG,
    url = "https://github.com/bazelbuild/rules_jvm_external/archive/%s.zip" % RULES_JVM_EXTERNAL_TAG,
)

load("@rules_jvm_external//:defs.bzl", "maven_install")

maven_install(
    artifacts = PROTOBUF_MAVEN_ARTIFACTS + ["com.google.cloud:google-cloud-kms:2.4.0"],
    generate_compat_repositories = True,
    repositories = [
        "https://repo.maven.apache.org/maven2/",
    ],
)

#############################################################################
# Temporary dependencies to be able to patch the java version of googleapis #
# TODO(b/234842124): drop once interoperable AES proto changes are released #
#############################################################################
http_archive(
    name = "com_google_api_codegen",
    sha256 = "65f72d3143bbcd53da37b04ec7d5dd647010a15272a004022e5b078552b64416",
    strip_prefix = "gapic-generator-857e2aab8017ecbb2abc9adc02d8571c02f94b3b",
    urls = ["https://github.com/googleapis/gapic-generator/archive/857e2aab8017ecbb2abc9adc02d8571c02f94b3b.zip"],
)

_gax_java_version = "2.18.1"

http_archive(
    name = "com_google_api_gax_java",
    sha256 = "0d7baa60f068a7f29da90e3ad61ebf2f3d19e7cb69a64903ae235498331cdac0",
    strip_prefix = "gax-java-%s" % _gax_java_version,
    urls = ["https://github.com/googleapis/gax-java/archive/v%s.zip" % _gax_java_version],
)

load("@com_google_api_gax_java//:repository_rules.bzl", "com_google_api_gax_java_properties")

com_google_api_gax_java_properties(
    name = "com_google_api_gax_java_properties",
    file = "@com_google_api_gax_java//:dependencies.properties",
)

load("@com_google_api_gax_java//:repositories.bzl", "com_google_api_gax_java_repositories")

com_google_api_gax_java_repositories()

load("@io_grpc_grpc_java//:repositories.bzl", "grpc_java_repositories")

grpc_java_repositories()

# Java microgenerator.
# Must go AFTER java-gax, since both java gax and gapic-generator are written in java and may conflict.
_gapic_generator_java_version = "2.8.2"

http_archive(
    name = "gapic_generator_java",
    sha256 = "93556f2040c38d5e51c6bb84cb66993ba1935d5a7dc82d1aaf4ce1093446c201",
    strip_prefix = "gapic-generator-java-%s" % _gapic_generator_java_version,
    urls = ["https://github.com/googleapis/gapic-generator-java/archive/v%s.zip" % _gapic_generator_java_version],
)

load("@gapic_generator_java//:repositories.bzl", "gapic_generator_java_repositories")

gapic_generator_java_repositories()

# gapic-generator transitive
# (goes AFTER java-gax, since both java gax and gapic-generator are written in java and may conflict)
load("@com_google_api_codegen//:repository_rules.bzl", "com_google_api_codegen_properties")

com_google_api_codegen_properties(
    name = "com_google_api_codegen_properties",
    file = "@com_google_api_codegen//:dependencies.properties",
)

load("@com_google_api_codegen//:repositories.bzl", "com_google_api_codegen_repositories")

http_archive(
    name = "com_google_protoc_java_resource_names_plugin",
    sha256 = "4b714b35ee04ba90f560ee60e64c7357428efcb6b0f3a298f343f8ec2c6d4a5d",
    strip_prefix = "protoc-java-resource-names-plugin-8d749cb5b7aa2734656e1ad36ceda92894f33153",
    urls = ["https://github.com/googleapis/protoc-java-resource-names-plugin/archive/8d749cb5b7aa2734656e1ad36ceda92894f33153.zip"],
)

com_google_api_codegen_repositories()

# protoc-java-resource-names-plugin (loaded in com_google_api_codegen_repositories())
# (required to support resource names feature in gapic generator)
load(
    "@com_google_protoc_java_resource_names_plugin//:repositories.bzl",
    "com_google_protoc_java_resource_names_plugin_repositories",
)

com_google_protoc_java_resource_names_plugin_repositories()
########################################################
# End of temporary java dependencies TODO(b/234842124) #
########################################################

# End: Googleapis Java dependencies

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
