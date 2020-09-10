#ifndef KMSP11_OPERATION_RSASSA_PSS_H_
#define KMSP11_OPERATION_RSASSA_PSS_H_

#include "absl/strings/string_view.h"
#include "kmsp11/operation/kms_signer.h"
#include "kmsp11/util/string_utils.h"
#include "openssl/rsa.h"

namespace kmsp11 {

// An implementation of SignerInterface that makes RSASSA-PSS signatures using
// Cloud KMS.
class RsaPssSigner : public KmsSigner {
 public:
  static absl::StatusOr<std::unique_ptr<SignerInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  size_t signature_length() override;

  virtual ~RsaPssSigner() {}

 private:
  RsaPssSigner(std::shared_ptr<Object> object, bssl::UniquePtr<RSA> key)
      : KmsSigner(object), key_(std::move(key)) {}

  bssl::UniquePtr<RSA> key_;
};

class RsaPssVerifier : public VerifierInterface {
 public:
  static absl::StatusOr<std::unique_ptr<VerifierInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  absl::Status Verify(KmsClient* client, absl::Span<const uint8_t> digest,
                      absl::Span<const uint8_t> signature) override;

  virtual ~RsaPssVerifier() {}

 private:
  RsaPssVerifier(std::shared_ptr<Object> object, bssl::UniquePtr<RSA> key)
      : object_(object), key_(std::move(key)) {}

  std::shared_ptr<Object> object_;
  bssl::UniquePtr<RSA> key_;
};

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_RSASSA_PSS_H_
