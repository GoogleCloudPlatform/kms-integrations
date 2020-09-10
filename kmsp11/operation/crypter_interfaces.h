#ifndef KMSP11_OPERATION_CRYPTER_INTERFACES_H_
#define KMSP11_OPERATION_CRYPTER_INTERFACES_H_

#include "absl/status/statusor.h"
#include "kmsp11/object.h"
#include "kmsp11/util/kms_client.h"

namespace kmsp11 {

class EncrypterInterface {
 public:
  virtual absl::StatusOr<absl::Span<const uint8_t>> Encrypt(
      KmsClient* client, absl::Span<const uint8_t> plaintext) = 0;

  virtual ~EncrypterInterface() {}
};

class DecrypterInterface {
 public:
  virtual absl::StatusOr<absl::Span<const uint8_t>> Decrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) = 0;

  virtual ~DecrypterInterface() {}
};

class SignerInterface {
 public:
  virtual const EVP_MD* digest_algorithm() = 0;
  virtual size_t signature_length() = 0;

  virtual absl::Status Sign(KmsClient* client, absl::Span<const uint8_t> data,
                            absl::Span<uint8_t> signature) = 0;

  virtual ~SignerInterface() {}
};

class VerifierInterface {
 public:
  virtual absl::Status Verify(KmsClient* client, absl::Span<const uint8_t> data,
                              absl::Span<const uint8_t> signature) = 0;
  virtual ~VerifierInterface() {}
};

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_CRYPTER_INTERFACES_H_
