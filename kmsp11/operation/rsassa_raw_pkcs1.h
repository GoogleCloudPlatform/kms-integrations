#ifndef KMSP11_OPERATION_RSASSA_RAW_PKCS1_H_
#define KMSP11_OPERATION_RSASSA_RAW_PKCS1_H_

#include "absl/strings/string_view.h"
#include "kmsp11/openssl.h"
#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/kms_client.h"
#include "kmsp11/util/string_utils.h"

namespace kmsp11 {

// An implementation of SignerInterface that makes "raw" RSASSA-PKCS1 signatures
// (i.e., without hashing/DigestInfo) using Cloud KMS.
class RsaRawPkcs1Signer : public SignerInterface {
 public:
  static absl::StatusOr<std::unique_ptr<SignerInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  size_t signature_length() override;

  absl::Status Sign(KmsClient* client, absl::Span<const uint8_t> data,
                    absl::Span<uint8_t> signature) override;

  virtual ~RsaRawPkcs1Signer() {}

 private:
  RsaRawPkcs1Signer(std::shared_ptr<Object> object, bssl::UniquePtr<RSA> key)
      : object_(object), key_(std::move(key)) {}

  std::shared_ptr<Object> object_;
  bssl::UniquePtr<RSA> key_;
};

class RsaRawPkcs1Verifier : public VerifierInterface {
 public:
  static absl::StatusOr<std::unique_ptr<VerifierInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  absl::Status Verify(KmsClient* client, absl::Span<const uint8_t> data,
                      absl::Span<const uint8_t> signature) override;

  virtual ~RsaRawPkcs1Verifier() {}

 private:
  RsaRawPkcs1Verifier(bssl::UniquePtr<RSA> key) : key_(std::move(key)) {}

  bssl::UniquePtr<RSA> key_;
};

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_RSASSA_RAW_PKCS1_H_
