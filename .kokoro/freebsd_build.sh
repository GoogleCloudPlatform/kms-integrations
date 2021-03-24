#!/usr/local/bin/bash

# Fail on any error.
set -e

# Display commands being run.
# WARNING: please only enable 'set -x' if necessary for debugging, and be very
#  careful if you handle credentials (e.g. from Keystore) with 'set -x':
#  statements like "export VAR=$(cat /tmp/keystore/credentials)" will result in
#  the credentials being printed in build logs.
#  Additionally, recursive invocation with credentials as command-line
#  parameters, will print the full command, with credentials, in the build logs.
# set -x

# Code under repo is checked out to ${KOKORO_ARTIFACTS_DIR}/git.
# The final directory name in this path is determined by the scm name specified
# in the job configuration.
export PROJECT_ROOT="${KOKORO_ARTIFACTS_DIR}/git/oss-tools"
cd "${PROJECT_ROOT}"

export RESULTS_DIR="${KOKORO_ARTIFACTS_DIR}/results"
mkdir "${RESULTS_DIR}"

# Use the 'latest' package repository so that we can get Bazel 4.0.0
# See https://www.freebsd.org/cgi/man.cgi?query=pkg.conf
sudo mkdir -p /usr/local/etc/pkg/repos
echo 'FreeBSD: { url: "pkg+http://pkg.FreeBSD.org/${ABI}/latest" }' |\
  sudo tee /usr/local/etc/pkg/repos/FreeBSD.conf
sudo pkg update -f
sudo pkg install -y bazel-4.0.0

# Make Bazel use a JDK that isn't a million years old, which fixes weird
# gRPC connection issues with remote build cache. :-(
export JAVA_HOME=/usr/local/openjdk11

# Configure user.bazelrc with remote build caching options
cp .kokoro/remote_cache.bazelrc user.bazelrc
echo "build --remote_default_exec_properties=cache-silo-key=freebsd" >> user.bazelrc

# Ensure that build outputs and test logs are uploaded even on failure
_upload_artifacts() {
  if [ -e "${PROJECT_ROOT}/bazel-bin/kmsp11/main/libkmsp11.so" ]; then
    cp "${PROJECT_ROOT}/bazel-bin/kmsp11/main/libkmsp11.so" \
      "${RESULTS_DIR}/libkmsp11.so"
  fi

  python3 "${PROJECT_ROOT}/.kokoro/copy_test_outputs.py" \
    "${PROJECT_ROOT}/bazel-testlogs" "${RESULTS_DIR}/testlogs"
}
trap _upload_artifacts EXIT

bazel test -c opt ${BAZEL_EXTRA_ARGS} ... :release_tests --keep_going
