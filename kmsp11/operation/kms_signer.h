#ifndef KMSP11_OPERATION_KMS_SIGNER_H_
#define KMSP11_OPERATION_KMS_SIGNER_H_

#include "absl/strings/string_view.h"
#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/util/string_utils.h"

namespace kmsp11 {

// An abstract SignerInterface that makes signatures using Cloud KMS.
class KmsSigner : public SignerInterface {
 public:
  inline const EVP_MD* digest_algorithm() override {
    return object_->algorithm().digest;
  }

  virtual absl::Status Sign(KmsClient* client, absl::Span<const uint8_t> digest,
                            absl::Span<uint8_t> signature) override;

  virtual ~KmsSigner() {}

 protected:
  KmsSigner(std::shared_ptr<Object> object) : object_(object) {}

  // Copy a signature from src to dest. Virtual in order to allow conversion
  // between signature types for ECDSA signatures.
  virtual absl::Status CopySignature(absl::string_view src,
                                     absl::Span<uint8_t> dest);

  Object* object() { return object_.get(); }

 private:
  std::shared_ptr<Object> object_;
};

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_KMS_SIGNER_H_
