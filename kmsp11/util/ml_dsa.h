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

#ifndef KMSP11_UTIL_ML_DSA_H_
#define KMSP11_UTIL_ML_DSA_H_

#include <string>
#include <string_view>

#include "absl/status/statusor.h"
#include "absl/types/span.h"
#include "common/kms_v1.h"
#include "kmsp11/cryptoki.h"

namespace cloud_kms::kmsp11 {

// Sizes (in bytes) of the FIPS 204 encodings for an ML-DSA parameter set.
struct MlDsaSizes {
  size_t public_key_bytes;
  size_t signature_bytes;
};

// An ML-DSA public key in the FIPS 204 encoding, tagged with its parameter set.
struct MlDsaPublicKey {
  CK_ML_DSA_PARAMETER_SET_TYPE parameter_set;
  std::string value;
};

// Returns the encoding sizes for the provided parameter set.
absl::StatusOr<MlDsaSizes> GetMlDsaSizes(
    CK_ML_DSA_PARAMETER_SET_TYPE parameter_set);

// Returns the ML-DSA parameter set for a Cloud KMS algorithm, or an error if
// the algorithm is not an ML-DSA algorithm.
absl::StatusOr<CK_ML_DSA_PARAMETER_SET_TYPE> MlDsaParameterSetForAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

// Returns true if the provided algorithm is an ML-DSA algorithm.
bool IsMlDsaAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

// Wraps a FIPS 204 encoded public key in a DER-encoded X.509
// SubjectPublicKeyInfo, using the algorithm identifiers from RFC 9881.
absl::StatusOr<std::string> MarshalMlDsaPublicKeyDer(
    CK_ML_DSA_PARAMETER_SET_TYPE parameter_set, std::string_view public_key);

// Parses a DER-encoded X.509 SubjectPublicKeyInfo containing an ML-DSA key.
absl::StatusOr<MlDsaPublicKey> ParseMlDsaPublicKeyDer(
    std::string_view public_key_der);

// Returns true if the crypto library that this binary was built with is able
// to verify ML-DSA signatures.
bool MlDsaVerificationSupported();

// Verifies an ML-DSA signature over `data` with the provided context string.
// Returns CKR_SIGNATURE_INVALID if the signature does not verify.
absl::Status MlDsaVerify(const MlDsaPublicKey& public_key,
                         absl::Span<const uint8_t> data,
                         absl::Span<const uint8_t> context,
                         absl::Span<const uint8_t> signature);

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_UTIL_ML_DSA_H_
