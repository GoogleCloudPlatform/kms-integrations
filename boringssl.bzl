# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@bazel_gazelle//internal:go_repository_cache.bzl", _read_go_env = "read_cache_env")

_BSSL_FIPS_BUILD_FILE_TEMPLATE = """
load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

filegroup(
    name = "bssl_sources",
    srcs = glob(["src/**"]),
)

cmake(
    name = "bssl_fips",
    targets = ["crypto", "ssl"],
    lib_source = ":bssl_sources",
    out_include_dir = "",
    out_lib_dir = "",
    out_static_libs = [
        "crypto/libcrypto.a",
        "ssl/libssl.a",
    ],
    install_prefix = ".",
    generate_args = ["-GNinja"],
    cache_entries = {
        "CMAKE_BUILD_TYPE": "Release",
        "FIPS": "1",
    },
    env = {
        "GOROOT": "%GOROOT%",
        "GOPATH": "%GOPATH%",
        "GOCACHE": "%GOCACHE%",
        "PATH": "%GOROOT%/bin:%GOPATH%/bin:${PATH}",
    },
)

filegroup(
    name = "bssl_fips_gen",
    srcs = [":bssl_fips"],
    output_group = "gen_dir",
)

genrule(
    name = "bssl_fips_static_libs",
    srcs = [":bssl_fips_gen"],
    cmd = "cp $(location bssl_fips_gen)/crypto/libcrypto.a $(@D); " +
          "cp $(location bssl_fips_gen)/ssl/libssl.a $(@D)",
    outs = ["libcrypto.a", "libssl.a"],
)

# This list from https://github.com/google/boringssl/blob/ae223d6138807a13006342edfeef32e813246b39/util/generate_build_files.py#L424
_ssl_headers = [
    "src/include/openssl/ssl.h",
    "src/include/openssl/tls1.h",
    "src/include/openssl/ssl3.h",
    "src/include/openssl/dtls1.h",
    "src/include/openssl/srtp.h",
]

_crypto_headers = glob(
    include = ["src/include/openssl/*.h"],
    exclude = _ssl_headers,
)

cc_library(
    name = "crypto",
    srcs = ["libcrypto.a"],
    hdrs = _crypto_headers,
    strip_include_prefix = "src/include",
    visibility = ["//visibility:public"],
)

cc_library(
    name = "ssl",
    srcs = ["libssl.a"],
    hdrs = _ssl_headers,
    deps = [":crypto"],
    strip_include_prefix = "src/include",
    visibility = ["//visibility:public"],
)
"""

_OPENSSL_BUILD_FILE_CONTENT = """
load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "crypto",
    hdrs = glob(["openssl/*.h"]),
    linkopts = ["-lcrypto"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "ssl",
    hdrs = glob(["openssl/*.h"]),
    deps = [":crypto"],
    linkopts = ["-lssl"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "openssl_compat",
    hdrs = ["compat/openssl/libcrypto-compat.h"],
    srcs = ["compat/openssl/libcrypto-compat.c"],
    strip_include_prefix = "compat",
    deps = [":crypto"],
    visibility = ["//visibility:public"],
)
"""

def _must_succeed(operation, result):
    if (result.return_code != 0):
        error_msg = (
            "{operation} failed, " +
            "return code {code}, stderr: {err}, stdout: {out}"
        ).format(
            operation = operation,
            code = result.return_code,
            err = result.stderr,
            out = result.stdout,
        )
        fail(error_msg)

def _crypto_library_impl(repo_ctx):
    library = repo_ctx.os.environ.get("KMSP11_CRYPTO_LIBRARY", default = "boringssl")
    if library not in ["boringssl", "boringssl_fips", "openssl"]:
        fail("KMSP11_CRYPTO_LIBRARY='%s' is not supported" % (library))

    if library == "boringssl":
        repo_ctx.download_and_extract(
            # 2021-03-18
            url = "https://github.com/google/boringssl/archive/dfa7c61bc554788901ee60940b30e5f3fc83f5ac.tar.gz",
            sha256 = "9f263cce1eb9d3429809637c8f62961e9f7b14d814902ca330a1678e9ddf49cd",
            stripPrefix = "boringssl-dfa7c61bc554788901ee60940b30e5f3fc83f5ac",
        )
        return

    if library == "openssl":
        include_dir = repo_ctx.os.environ.get(
            "OPENSSL_INCLUDE_DIR",
            default = "/usr/include/openssl",
        )
        repo_ctx.symlink(include_dir, "openssl")

        # See https://wiki.openssl.org/index.php/OpenSSL_1.1.0_Changes#Backward_compatibility
        repo_ctx.download_and_extract(
            url = "https://wiki.openssl.org/images/e/ed/Openssl-compat.tar.gz",
            sha256 = "2d75ffb10b2e3138a9c4e3c130fede955c5b8e326e6a860b718a99e41df58abb",
            output = "compat/openssl",
        )
        repo_ctx.patch(Label("//:third_party/openssl_compat.patch"))

        repo_ctx.file(
            "BUILD",
            content = _OPENSSL_BUILD_FILE_CONTENT,
        )
        return

    # Proceeding to set up BoringSSL + FIPS config

    # ae223d6138807a13006342edfeef32e813246b39 is the latest FIPS-validated version.
    # https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3678.pdf
    repo_ctx.download_and_extract(
        url = "https://github.com/google/boringssl/archive/ae223d6138807a13006342edfeef32e813246b39.tar.gz",
        stripPrefix = "boringssl-ae223d6138807a13006342edfeef32e813246b39",
        sha256 = "06cb9d317001e026bde318d47a532a31651c68c7cf788ce0c30327f2d5e6b639",
        output = "src",
    )

    fips_patches = [
        # From upstream at 05cd93068b0a553afc48f69acbceae10c6a17593 and
        # 1e547722d412a77f2708bf92cfef75c287d2cb9e; needed to build with
        # clang+llvm.
        Label("//:third_party/bssl_clang_fallthrough.patch"),
        # Specific to our builds. Needed to ensure that symbols are exposed
        # transitively within the Bazel ecosystem.
        Label("//:third_party/bssl_visibility.patch"),
    ]

    if repo_ctx.os.name == "freebsd":
        # Based on upstream at c953ee4af7ad385a82709d33ed3116f5900343d4;
        # required to compile the BoringSSL RNG on FreeBSD.
        fips_patches += [Label("//:third_party/bssl_fips_random_freebsd.patch")]

    for patch in fips_patches:
        _must_succeed(
            "patch for bssl fips",
            repo_ctx.execute([
                "patch",
                "-d",
                "src",
                "-i",
                repo_ctx.path(patch),
                "-E",
                "-p1",
            ]),
        )

    repo_ctx.file(
        "BUILD.tmpl",
        content = _BSSL_FIPS_BUILD_FILE_TEMPLATE,
        executable = False,
    )

    go_env = _read_go_env(repo_ctx, str(repo_ctx.path(repo_ctx.attr._go_cache)))
    repo_ctx.template(
        "BUILD",
        "BUILD.tmpl",
        substitutions = {
            "%GOROOT%": go_env["GOROOT"],
            "%GOPATH%": go_env["GOPATH"],
            "%GOCACHE%": "$BUILD_TMPDIR/cache",
            "%SYSTEM_NAME%": repo_ctx.os.name,
        },
        executable = False,
    )

crypto_library = repository_rule(
    implementation = _crypto_library_impl,
    attrs = {
        "_go_cache": attr.label(
            default = Label("@bazel_gazelle_go_repository_cache//:go.env"),
            allow_single_file = True,
        ),
    },
    environ = [
        "KMSP11_CRYPTO_LIBRARY",
        "OPENSSL_INCLUDE_DIR",
    ],
)

def select_crypto_library():
    if native.existing_rule("boringssl"):
        return

    # Our crypto repository will always be named 'boringssl' so that our
    # gRPC stack uses it as well.
    crypto_library(name = "boringssl")
