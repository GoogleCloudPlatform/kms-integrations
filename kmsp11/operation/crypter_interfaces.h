#ifndef KMSP11_OPERATION_CRYPTER_INTERFACES_H_
#define KMSP11_OPERATION_CRYPTER_INTERFACES_H_

#include "kmsp11/object.h"
#include "kmsp11/util/kms_client.h"
#include "kmsp11/util/status_or.h"

namespace kmsp11 {

class DecrypterInterface {
 public:
  virtual StatusOr<absl::Span<const uint8_t>> Decrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) = 0;

  virtual ~DecrypterInterface() {}
};

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_CRYPTER_INTERFACES_H_
