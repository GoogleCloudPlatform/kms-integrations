#!/usr/local/bin/bash
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

# Install package dependencies. Stored in GCS since FreeBSD11 repos
# have been turned down.
tar zxvf ${KOKORO_GFILE_DIR}/freebsd11-amd64-packages.tar.gz -C ${KOKORO_ARTIFACTS_DIR}
pushd ${KOKORO_ARTIFACTS_DIR}/freebsd11-amd64-packages
#  Required for BoringSSL FIPS builds.
sudo pkg add cmake-3.19.2.txz
sudo pkg add ninja-1.10.2,2.txz
# Required for building Bazel from source
sudo pkg add openjdk8-8.275.01.1.txz
sudo pkg add bazel-4.2.1.txz
sudo pkg add unzip-6.0_8.txz
sudo pkg add zip-3.0_1.txz
popd

# Make Bazel use a JDK that isn't a million years old, which fixes weird
# gRPC connection issues with remote build cache. :-(
export JAVA_HOME=/usr/local/openjdk11

# Configure user.bazelrc with remote build caching options
cp .kokoro/remote_cache.bazelrc user.bazelrc
echo "build --remote_default_exec_properties=cache-silo-key=freebsd" >> user.bazelrc

# Build a more modern Bazel than what's on FreeBSD 11. :-(
pushd build/bazel
bazel --bazelrc=${PROJECT_ROOT}/user.bazelrc build :bazel > ${RESULTS_DIR}/bazel_build.log
shopt -s expand_aliases
alias local_bazel=`pwd`/bazel-bin/bazel
popd
# Fail loudly if it's the wrong version.
local_bazel version | grep $(cat .bazelversion)

# Ensure that build outputs and test logs are uploaded even on failure
_upload_artifacts() {
  if [ -e "${PROJECT_ROOT}/bazel-bin/kmsp11/main/libkmsp11.so" ]; then
    cp "${PROJECT_ROOT}/bazel-bin/kmsp11/main/libkmsp11.so" \
      "${RESULTS_DIR}/libkmsp11.so"
  fi
  if [ -e "${PROJECT_ROOT}/bazel-bin/kmsp11/test/e2e/e2e_test" ]; then
    cp "${PROJECT_ROOT}/bazel-bin/kmsp11/test/e2e/e2e_test" \
      "${RESULTS_DIR}/e2e_test"
  fi

  cp "${PROJECT_ROOT}/LICENSE" "${RESULTS_DIR}"
  cp "${PROJECT_ROOT}/NOTICE" "${RESULTS_DIR}"

  python3 "${PROJECT_ROOT}/.kokoro/copy_test_outputs.py" \
    "${PROJECT_ROOT}/bazel-testlogs" "${RESULTS_DIR}/testlogs"
}
trap _upload_artifacts EXIT

# Ensure Bazel version information is included in the build log
local_bazel version

export BAZEL_ARGS="-c opt --keep_going ${BAZEL_EXTRA_ARGS}"

local_bazel test ${BAZEL_ARGS} ... :ci_only_tests

local_bazel run ${BAZEL_ARGS} //kmsp11/tools/buildsigner -- \
  -signing_key=${BUILD_SIGNING_KEY} \
  < bazel-bin/kmsp11/main/libkmsp11.so \
  > ${RESULTS_DIR}/libkmsp11.so.sig
