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

#ifndef KMSP11_OPERATION_ECDSA_H_
#define KMSP11_OPERATION_ECDSA_H_

#include <string_view>

#include "kmsp11/openssl.h"
#include "kmsp11/operation/kms_prehashed_signer.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/string_utils.h"

namespace kmsp11 {

// An implementation of SignerInterface that makes ECDSA signatures using Cloud
// KMS.
class EcdsaSigner : public KmsPrehashedSigner {
 public:
  static absl::StatusOr<std::unique_ptr<SignerInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  size_t signature_length() override;

  absl::Status CopySignature(std::string_view src,
                             absl::Span<uint8_t> dest) override;

  virtual ~EcdsaSigner() {}

 private:
  EcdsaSigner(std::shared_ptr<Object> object, bssl::UniquePtr<EC_KEY> key)
      : KmsPrehashedSigner(object), key_(std::move(key)) {}

  bssl::UniquePtr<EC_KEY> key_;
};

class EcdsaVerifier : public VerifierInterface {
 public:
  static absl::StatusOr<std::unique_ptr<VerifierInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  Object* object() override { return object_.get(); };

  absl::Status Verify(KmsClient* client, absl::Span<const uint8_t> digest,
                      absl::Span<const uint8_t> signature) override;
  absl::Status VerifyUpdate(KmsClient* client,
                            absl::Span<const uint8_t> data) override;
  absl::Status VerifyFinal(KmsClient* client,
                           absl::Span<const uint8_t> signature) override;

  virtual ~EcdsaVerifier() {}

 private:
  EcdsaVerifier(std::shared_ptr<Object> object, bssl::UniquePtr<EC_KEY> key)
      : object_(object), key_(std::move(key)) {}

  std::shared_ptr<Object> object_;
  bssl::UniquePtr<EC_KEY> key_;
};

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_ECDSA_H_
