/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KMSP11_UTIL_KMS_CLIENT_SERVICE_CONFIG_H_
#define KMSP11_UTIL_KMS_CLIENT_SERVICE_CONFIG_H_

#include <string_view>

namespace kmsp11 {

// TODO(bdhess): Pull this in dynamically from the Bazel dependency
// once cl/362932396 is available in the googleapis version we consume.
constexpr std::string_view kDefaultKmsServiceConfig = R"(
{
  "methodConfig": [
    {
      "name": [
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "CreateCryptoKeyVersion"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "ImportCryptoKeyVersion"
        }
      ],
      "timeout": "60s"
    },
    {
      "name": [
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "ListKeyRings"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "ListImportJobs"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "ListCryptoKeys"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "ListCryptoKeyVersions"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "GetKeyRing"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "GetImportJob"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "GetCryptoKey"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "GetCryptoKeyVersion"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "CreateKeyRing"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "CreateImportJob"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "CreateCryptoKey"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "UpdateCryptoKey"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "UpdateCryptoKeyVersion"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "Encrypt"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "Decrypt"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "UpdateCryptoKeyPrimaryVersion"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "DestroyCryptoKeyVersion"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "RestoreCryptoKeyVersion"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "GetPublicKey"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "AsymmetricDecrypt"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "AsymmetricSign"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "SetIamPolicy"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "GetIamPolicy"
        },
        {
          "service": "google.cloud.kms.v1.KeyManagementService",
          "method": "TestIamPermissions"
        }
      ],
      "timeout": "60s",
      "retryPolicy": {
        "initialBackoff": "0.100s",
        "maxBackoff": "60s",
        "backoffMultiplier": 1.3,
        "maxAttempts": 5,
        "retryableStatusCodes": [
          "UNAVAILABLE",
          "DEADLINE_EXCEEDED"
        ]
      }
    }
  ]
}
)";
}  // namespace kmsp11

#endif  // KMSP11_UTIL_KMS_CLIENT_SERVICE_CONFIG_H_
