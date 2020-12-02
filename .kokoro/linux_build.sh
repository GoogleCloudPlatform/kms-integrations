#!/bin/bash

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

# Add the latest version of Bazel to the PATH
use_bazel.sh 3.3.0

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

# Force bazel to statically link libstdc++
# See https://github.com/bazelbuild/bazel/pull/8660
BAZEL_LINKOPTS="-static-libstdc++ -static-libgcc" \
  BAZEL_LINKLIBS="-l%:libstdc++.a -lm" \
  bazel test -c opt ${BAZEL_EXTRA_ARGS} ... --keep_going
