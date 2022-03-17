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

#ifndef KMSP11_OPERATION_RSASSA_PKCS1_H_
#define KMSP11_OPERATION_RSASSA_PKCS1_H_

#include <string_view>

#include "kmsp11/openssl.h"
#include "kmsp11/operation/kms_prehashed_signer.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/string_utils.h"

namespace kmsp11 {

// An implementation of SignerInterface that makes RSASSA-PKCS1 signatures using
// Cloud KMS.
class RsaPkcs1Signer : public KmsPrehashedSigner {
 public:
  static absl::StatusOr<std::unique_ptr<SignerInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  size_t signature_length() override;

  absl::Status Sign(KmsClient* client, absl::Span<const uint8_t> data,
                    absl::Span<uint8_t> signature) override;

  virtual ~RsaPkcs1Signer() {}

 private:
  RsaPkcs1Signer(std::shared_ptr<Object> object, bssl::UniquePtr<RSA> key)
      : KmsPrehashedSigner(object), key_(std::move(key)) {}

  bssl::UniquePtr<RSA> key_;
};

class RsaPkcs1Verifier : public VerifierInterface {
 public:
  static absl::StatusOr<std::unique_ptr<VerifierInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  absl::Status Verify(KmsClient* client, absl::Span<const uint8_t> data,
                      absl::Span<const uint8_t> signature) override;

  virtual ~RsaPkcs1Verifier() {}

 private:
  RsaPkcs1Verifier(std::shared_ptr<Object> object, bssl::UniquePtr<RSA> key)
      : object_(object), key_(std::move(key)) {}

  std::shared_ptr<Object> object_;
  bssl::UniquePtr<RSA> key_;
};

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_RSASSA_PKCS1_H_
