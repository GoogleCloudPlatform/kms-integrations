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
cd ${KOKORO_ARTIFACTS_DIR}/git/oss-tools

export RESULTS_DIR=${KOKORO_ARTIFACTS_DIR}/results
mkdir ${RESULTS_DIR}

# Add the latest version of Bazel to the PATH
use_bazel.sh latest

# Ensure that test logs are uploaded on failure
_backup_artifacts() {
  # go/kokoro/userdocs/general/custom_test_logs.md#converting-bazel-test-logs-to-spongeresultstore-test-logs
  rsync -aL --include='*/' --include='*test.log' --include='*test.xml' \
    --exclude='*' --prune-empty-dirs bazel-testlogs/ ${RESULTS_DIR}/
  find ${RESULTS_DIR} -name 'test.log' \
    -exec rename 's/test.log/sponge_log.log/' {} \;
  find ${RESULTS_DIR} -name 'test.xml' \
    -exec rename 's/test.xml/sponge_log.xml/' {} \;
}
trap _backup_artifacts EXIT

bazel test ...

