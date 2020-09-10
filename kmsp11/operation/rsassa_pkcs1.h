#ifndef KMSP11_OPERATION_RSASSA_PKCS1_H_
#define KMSP11_OPERATION_RSASSA_PKCS1_H_

#include "absl/strings/string_view.h"
#include "kmsp11/operation/kms_signer.h"
#include "kmsp11/util/string_utils.h"
#include "openssl/rsa.h"

namespace kmsp11 {

// An implementation of SignerInterface that makes RSASSA-PKCS1 signatures using
// Cloud KMS.
class RsaPkcs1Signer : public KmsSigner {
 public:
  static absl::StatusOr<std::unique_ptr<SignerInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  size_t signature_length() override;

  absl::Status Sign(KmsClient* client, absl::Span<const uint8_t> data,
                    absl::Span<uint8_t> signature) override;

  virtual ~RsaPkcs1Signer() {}

 private:
  RsaPkcs1Signer(std::shared_ptr<Object> object, bssl::UniquePtr<RSA> key)
      : KmsSigner(object), key_(std::move(key)) {}

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
