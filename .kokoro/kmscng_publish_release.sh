#!/bin/bash
# Copyright 2026 Google LLC
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


# Code under repo is checked out to ${KOKORO_ARTIFACTS_DIR}/git.
# The final directory name in this path is determined by the scm name specified
# in the job configuration.
export PROJECT_ROOT="${KOKORO_ARTIFACTS_DIR}/git/oss-tools"
cd "${PROJECT_ROOT}"

# Get provider version
export CNG_VERSION=$(grep "uint8_t kLibraryVersion" "${PROJECT_ROOT}/kmscng/version.h" | \
    sed 's/.*= \([0-9]*\);.*/\1/' | \
    paste -sd. -)

MANIFEST_FILE="manifest.json"
cat <<EOF > $MANIFEST_FILE
{
  "publish_all": false,
  "publishing_groups": [
    {
      "packages": [
        {
          "name": " kmscng-windows-amd64",
          "version": "${CNG_VERSION}"
        }
      ]
    }
  ],
  "registry_config": {
    "github_releases": {
      "name": "CNG Provider v${CNG_VERSION}",
      "tag": "cng-v${CNG_VERSION}"
    }
  }
}
EOF

gcloud storage cp --no-clobber --quiet "$MANIFEST_FILE" \
    "gs://oss-exit-gate-prod-projects-bucket/kms-integrations/githubreleases/manifests/$MANIFEST_FILE"
