// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "kmsp11/operation/kms_digesting_signer.h"

#include "kmsp11/operation/ecdsa.h"
#include "kmsp11/operation/kms_prehashed_signer.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_macros.h"

namespace kmsp11 {

absl::StatusOr<std::unique_ptr<SignerInterface>> KmsDigestingSigner::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  CK_MECHANISM inner_mechanism{CKM_ECDSA, nullptr, 0};
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_EC, CKO_PRIVATE_KEY,
                                        inner_mechanism.mechanism, key.get()));
  RETURN_IF_ERROR(EnsureNoParameters(mechanism));

  ASSIGN_OR_RETURN(std::unique_ptr<SignerInterface> inner_signer,
                   EcdsaSigner::New(key, &inner_mechanism));
  bssl::UniquePtr<EVP_MD_CTX> ctx(EVP_MD_CTX_new());

  return std::unique_ptr<SignerInterface>(
      new KmsDigestingSigner(std::move(inner_signer), std::move(ctx)));
}

absl::Status KmsDigestingSigner::Sign(KmsClient* client,
                                      absl::Span<const uint8_t> data,
                                      absl::Span<uint8_t> signature) {
  ASSIGN_OR_RETURN(const EVP_MD* md,
                   DigestForMechanism(*object()->algorithm().digest_mechanism));

  if (EVP_DigestInit(md_ctx_.get(), md) != 1) {
    return NewInternalError(
        absl::StrFormat(
            "failed while initializing EVP digest with digest size %d",
            EVP_MD_size(md)),
        SOURCE_LOCATION);
  }

  if (EVP_DigestUpdate(md_ctx_.get(), data.data(), data.size()) != 1) {
    return NewInternalError("failed while updating EVP digest with input data",
                            SOURCE_LOCATION);
  }

  std::vector<uint8_t> evp_digest(EVP_MD_size(md));
  unsigned int digest_len;
  if (EVP_DigestFinal(md_ctx_.get(), evp_digest.data(), &digest_len) != 1) {
    return NewInternalError("failed while finalizing EVP digest",
                            SOURCE_LOCATION);
  }

  if (digest_len != EVP_MD_size(md)) {
    return NewInternalError(
        absl::StrFormat("computed digest has incorrect size (got %d, want %d)",
                        digest_len, EVP_MD_size(md)),
        SOURCE_LOCATION);
  }

  return inner_signer_->Sign(client, evp_digest, signature);
}

size_t KmsDigestingSigner::signature_length() {
  return inner_signer_->signature_length();
}

}  // namespace kmsp11
