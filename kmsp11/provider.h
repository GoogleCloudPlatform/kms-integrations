#ifndef KMSP11_PROVIDER_H_
#define KMSP11_PROVIDER_H_

#include "kmsp11/cryptoki.h"
#include "kmsp11/util/status_or.h"

namespace kmsp11 {

// Provider models a "run" of a Cryptoki library, from C_Initialize to
// C_Finalize.
//
// See go/kms-pkcs11-model
class Provider {
 public:
  static StatusOr<Provider> New();

  const CK_INFO& info() { return info_; }

 private:
  Provider(CK_INFO info) : info_(info) {}
  CK_INFO info_;
};

}  // namespace kmsp11

#endif  // KMSP11_PROVIDER_H_
