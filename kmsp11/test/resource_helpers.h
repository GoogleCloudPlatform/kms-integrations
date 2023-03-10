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

#ifndef KMSP11_TEST_RESOURCE_HELPERS_H_
#define KMSP11_TEST_RESOURCE_HELPERS_H_

#include <string_view>

#include "absl/time/time.h"
#include "common/kms_v1.h"
#include "common/test/test_status_macros.h"
#include "fakekms/cpp/fakekms.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.grpc.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "kmsp11/object.h"
#include "kmsp11/openssl.h"

namespace cloud_kms::kmsp11 {

// A location name where test resources should be created.
ABSL_CONST_INIT extern const std::string_view kTestLocation;

// Creates a KeyRing with the provided attributes, or CHECK-fails.
kms_v1::KeyRing CreateKeyRingOrDie(kms_v1::KeyManagementService::Stub* kms_stub,
                                   std::string_view location_name,
                                   std::string_view key_ring_id,
                                   const kms_v1::KeyRing& key_ring);

// Creates a CryptoKey with the provided attributes, or CHECK-fails.
kms_v1::CryptoKey CreateCryptoKeyOrDie(
    kms_v1::KeyManagementService::Stub* kms_stub,
    std::string_view key_ring_name, std::string_view crypto_key_id,
    const kms_v1::CryptoKey& crypto_key, bool skip_initial_version_creation);

// Creates a CryptoKeyVersion with the provided attributes, or CHECK-fails.
kms_v1::CryptoKeyVersion CreateCryptoKeyVersionOrDie(
    kms_v1::KeyManagementService::Stub* kms_stub,
    std::string_view crypto_key_name,
    const kms_v1::CryptoKeyVersion& crypto_key_version);

// Gets a CryptoKey with the provided name, or CHECK-fails.
kms_v1::CryptoKey GetCryptoKeyOrDie(
    kms_v1::KeyManagementService::Stub* kms_stub,
    std::string_view crypto_key_name);

// Gets a CryptoKeyVersion with the provided name, or CHECK-fails.
kms_v1::CryptoKeyVersion GetCryptoKeyVersionOrDie(
    kms_v1::KeyManagementService::Stub* kms_stub,
    std::string_view crypto_key_version_name);

// Invokes GetCryptoKeyVersion in a loop, waiting poll_interval between each
// request, until the specified CryptoKeyVersion's state is ENABLED.
kms_v1::CryptoKeyVersion WaitForEnablement(
    kms_v1::KeyManagementService::Stub* kms_stub,
    const kms_v1::CryptoKeyVersion& crypto_key_version,
    absl::Duration poll_interval = absl::Milliseconds(1));

// Updates a CryptoKeyVersion with the provided attributes, or CHECK-fails.
kms_v1::CryptoKeyVersion UpdateCryptoKeyVersionOrDie(
    kms_v1::KeyManagementService::Stub* kms_stub,
    const kms_v1::CryptoKeyVersion& crypto_key_version,
    const google::protobuf::FieldMask& update_mask);

// Gets the public key for the provided CryptoKeyVersion.
kms_v1::PublicKey GetPublicKey(
    kms_v1::KeyManagementService::Stub* kms_stub,
    const kms_v1::CryptoKeyVersion& crypto_key_version);

// Returns a randomized string suitable for use as a KMS resource identifier.
std::string RandomId(std::string_view prefix = "test-");

// Returns a mock KeyPair with the provided algorithm and public key.
absl::StatusOr<KeyPair> NewMockKeyPair(
    google::cloud::kms::v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm
        algorithm,
    std::string_view public_key_runfile);

// Returns a mock Object with the provided algorithm.
absl::StatusOr<Object> NewMockSecretKey(
    google::cloud::kms::v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm
        algorithm);

// Retrieves the public key associated with the private key and parses it in
// EVP_PKEY format.
absl::StatusOr<bssl::UniquePtr<EVP_PKEY>> GetEVPPublicKey(
    fakekms::Server* fake_server, kms_v1::CryptoKeyVersion ckv);

// Returns the object handle for the private key associated with the specified
// crypto key version.
absl::StatusOr<CK_OBJECT_HANDLE> GetPrivateKeyObjectHandle(
    CK_SESSION_HANDLE session, kms_v1::CryptoKeyVersion ckv);

// Returns the object handle for the public key associated with the specified
// crypto key version.
absl::StatusOr<CK_OBJECT_HANDLE> GetPublicKeyObjectHandle(
    CK_SESSION_HANDLE session, kms_v1::CryptoKeyVersion ckv);

// Returns the object handle for the secret key associated with the specified
// crypto key version.
absl::StatusOr<CK_OBJECT_HANDLE> GetSecretKeyObjectHandle(
    CK_SESSION_HANDLE session, kms_v1::CryptoKeyVersion ckv);

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_TEST_RESOURCE_HELPERS_H_
