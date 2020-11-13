#ifndef KMSP11_OPERATION_ECDSA_H_
#define KMSP11_OPERATION_ECDSA_H_

#include "absl/strings/string_view.h"
#include "kmsp11/operation/kms_digest_signer.h"
#include "kmsp11/util/string_utils.h"
#include "openssl/ec_key.h"

namespace kmsp11 {

// An implementation of SignerInterface that makes ECDSA signatures using Cloud
// KMS.
class EcdsaSigner : public KmsDigestSigner {
 public:
  static absl::StatusOr<std::unique_ptr<SignerInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  size_t signature_length() override;

  absl::Status CopySignature(absl::string_view src,
                             absl::Span<uint8_t> dest) override;

  virtual ~EcdsaSigner() {}

 private:
  EcdsaSigner(std::shared_ptr<Object> object, bssl::UniquePtr<EC_KEY> key)
      : KmsDigestSigner(object), key_(std::move(key)) {}

  bssl::UniquePtr<EC_KEY> key_;
};

class EcdsaVerifier : public VerifierInterface {
 public:
  static absl::StatusOr<std::unique_ptr<VerifierInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  absl::Status Verify(KmsClient* client, absl::Span<const uint8_t> digest,
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
