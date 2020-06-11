#include "kmsp11/operation/crypter_ops.h"

#include "kmsp11/operation/rsaes_oaep.h"
#include "kmsp11/util/errors.h"

namespace kmsp11 {

StatusOr<DecryptOp> NewDecryptOp(std::shared_ptr<Object> key,
                                 const CK_MECHANISM* mechanism) {
  switch (mechanism->mechanism) {
    case CKM_RSA_PKCS_OAEP:
      return RsaOaepDecrypter::New(key, mechanism);
    default:
      return InvalidMechanismError(mechanism->mechanism, "decrypt",
                                   SOURCE_LOCATION);
  }
}

}  // namespace kmsp11