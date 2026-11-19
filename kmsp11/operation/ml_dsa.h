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

#ifndef KMSP11_OPERATION_ML_DSA_H_
#define KMSP11_OPERATION_ML_DSA_H_

#include "kmsp11/operation/crypter_interfaces.h"

namespace cloud_kms::kmsp11 {

// The largest message that Cloud KMS accepts in AsymmetricSignRequest.data.
inline constexpr size_t kMaxMlDsaMessageBytes = 64 * 1024;

// Returns a signer for CKM_ML_DSA (PKCS #11 v3.2). Signing is performed by
// Cloud KMS over the full message, using the AsymmetricSign RPC.
//
// The optional mechanism parameter is a CK_SIGN_ADDITIONAL_CONTEXT. Cloud KMS
// produces hedged (randomized) signatures with an empty context, so the
// context must be empty and CKH_DETERMINISTIC_REQUIRED is rejected.
absl::StatusOr<std::unique_ptr<SignerInterface>> NewMlDsaSigner(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

// Returns a verifier for CKM_ML_DSA. Verification is performed locally, and
// fails with CKR_MECHANISM_INVALID if the crypto library this module was built
// with does not support ML-DSA.
absl::StatusOr<std::unique_ptr<VerifierInterface>> NewMlDsaVerifier(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_OPERATION_ML_DSA_H_
