/*
 * Copyright 2026 Google LLC
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

#ifndef KMSP11_TEST_ML_DSA_FAKE_KMS_H_
#define KMSP11_TEST_ML_DSA_FAKE_KMS_H_

#include <memory>
#include <string>

#include "absl/status/statusor.h"
#include "common/kms_v1.h"

namespace cloud_kms::kmsp11 {

// An in-process fake of the Cloud KMS gRPC API that supports ML-DSA keys.
//
// The Go fakekms server is built against a Cloud KMS client library that
// predates post-quantum algorithms, so this C++ fake is used to exercise the
// ML-DSA code paths. It implements ListCryptoKeys, ListCryptoKeyVersions,
// GetPublicKey (NIST_PQC format only) and AsymmetricSign (data only).
//
// The fake signs with BoringSSL's ML-DSA implementation, so New() returns
// kUnimplemented when built against a crypto library without ML-DSA.
class MlDsaFakeKms {
 public:
  static absl::StatusOr<std::unique_ptr<MlDsaFakeKms>> New();
  virtual ~MlDsaFakeKms() = default;

  virtual const std::string& listen_addr() const = 0;

  // Creates an enabled ML-DSA CryptoKeyVersion (and its parent CryptoKey) in
  // the provided key ring, and returns it.
  virtual absl::StatusOr<kms_v1::CryptoKeyVersion> CreateKey(
      std::string_view key_ring_name, std::string_view key_id,
      kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) = 0;

  // Returns the number of AsymmetricSign calls served.
  virtual int sign_count() const = 0;

  // Causes AsymmetricSign to return a corrupted signature, for testing.
  virtual void set_corrupt_signatures(bool corrupt) = 0;
};

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_TEST_ML_DSA_FAKE_KMS_H_
