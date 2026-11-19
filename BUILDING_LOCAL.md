# Building on this machine

Notes on building and testing the PKCS #11 library on this workstation (Ubuntu
22.04, x86_64). See [BUILDING.md](BUILDING.md) for the project's official build
documentation.

## Prerequisites

### Bazel 6.4.0

The project pins Bazel 6.4.0 in `.bazelversion`. Only Bazel 5.4.1 is installed
system-wide here (`/usr/bin/bazel-5.4.1`), so use
[bazelisk](https://github.com/bazelbuild/bazelisk), which downloads the pinned
version automatically:

```sh
mkdir -p ~/.local/bin
curl -fL -o ~/.local/bin/bazel \
  https://github.com/bazelbuild/bazelisk/releases/download/v1.25.0/bazelisk-linux-amd64
chmod +x ~/.local/bin/bazel
bazel version   # should report "Build label: 6.4.0"
```

### Compiler: use gcc

clang 14 on this machine selects the GCC 12 toolchain, but only the GCC 11 C++
headers are installed, so clang fails with `fatal error: 'array' file not
found`. Build with gcc instead by setting `CC`/`CXX` on every Bazel command:

```sh
export CC=gcc CXX=g++
```

Bazel caches the toolchain it detects, so if you previously built with clang,
run `bazel clean --expunge` once after switching.

## Build

Build the shared library:

```sh
CC=gcc CXX=g++ bazel build //kmsp11/main:libkmsp11.so
```

The output is `bazel-bin/kmsp11/main/libkmsp11.so`.

Build everything that builds on Linux (library, tests, e2e binaries and the Go
fake KMS server):

```sh
CC=gcc CXX=g++ bazel build --keep_going //kmsp11/... //common/... //fakekms/...
```

## Test

Run all unit and integration tests, excluding the e2e tests (those need real
Cloud KMS credentials):

```sh
CC=gcc CXX=g++ bazel test --keep_going //kmsp11/... //common/... -- -//kmsp11/test/e2e/...
```

Run only the ML-DSA tests:

```sh
CC=gcc CXX=g++ bazel test \
  //kmsp11/util:ml_dsa_test \
  //kmsp11/operation:ml_dsa_test \
  //kmsp11:object_loader_ml_dsa_test \
  //kmsp11/main:bridge_test
```

Test logs are in `bazel-testlogs/<package>/<target>/test.log`. Add
`--test_output=errors` to print the logs of failing tests to the terminal.

The ML-DSA tests use an in-process C++ fake KMS (`kmsp11/test/ml_dsa_fake_kms`)
rather than the Go `fakekms` server, whose Cloud KMS client predates
post-quantum algorithms. On builds whose crypto library lacks ML-DSA (FIPS
BoringSSL, OpenSSL), the fake reports itself unavailable and those tests are
skipped.

## Alternative crypto libraries

These configurations were **not** built on this machine; each first build sets
up its crypto library and takes several extra minutes. ML-DSA signing works in
both, but ML-DSA verification is unavailable.

```sh
# FIPS-validated BoringSSL (builds BoringSSL with CMake and Go)
CC=gcc CXX=g++ bazel build --config fips //kmsp11/main:libkmsp11.so

# System OpenSSL
CC=gcc CXX=g++ bazel build --config openssl //kmsp11/main:libkmsp11.so
```

## Expected build times

Measured on this machine with gcc and the default BoringSSL:

| Scenario | Time |
|---|---|
| Clean build, empty cache (downloads deps; compiles gRPC, protobuf, abseil, BoringSSL) | ~11 min |
| After changing a dependency pin in `WORKSPACE` or `boringssl.bzl` | ~8 min |
| Incremental: edit library code, rebuild and run all tests | ~30 s |
| No-op rebuild | ~3 s |

## Not buildable here

- `//kmscng/...`: the CNG provider is Windows-only.
- e2e tests (`//kmsp11/test/e2e/...`): their binaries build, but running them
  requires credentials for real Cloud KMS.
