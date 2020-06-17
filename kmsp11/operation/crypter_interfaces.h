#ifndef KMSP11_OPERATION_CRYPTER_INTERFACES_H_
#define KMSP11_OPERATION_CRYPTER_INTERFACES_H_

#include "kmsp11/object.h"
#include "kmsp11/util/kms_client.h"
#include "kmsp11/util/status_or.h"

namespace kmsp11 {

class EncrypterInterface {
 public:
  virtual StatusOr<absl::Span<const uint8_t>> Encrypt(
      KmsClient* client, absl::Span<const uint8_t> plaintext) = 0;

  virtual ~EncrypterInterface() {}
};

class DecrypterInterface {
 public:
  virtual StatusOr<absl::Span<const uint8_t>> Decrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) = 0;

  virtual ~DecrypterInterface() {}
};

class SignerInterface {
 public:
  virtual const EVP_MD* digest_algorithm() = 0;
  virtual size_t signature_length() = 0;

  virtual absl::Status Sign(KmsClient* client, absl::Span<const uint8_t> digest,
                            absl::Span<uint8_t> signature) = 0;

  virtual ~SignerInterface() {}
};

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_CRYPTER_INTERFACES_H_
