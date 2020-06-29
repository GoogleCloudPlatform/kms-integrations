#include "kmsp11/operation/crypter_ops.h"

#include "kmsp11/operation/ecdsa.h"
#include "kmsp11/operation/rsaes_oaep.h"
#include "kmsp11/operation/rsassa_pkcs1.h"
#include "kmsp11/operation/rsassa_pss.h"
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

StatusOr<EncryptOp> NewEncryptOp(std::shared_ptr<Object> key,
                                 const CK_MECHANISM* mechanism) {
  switch (mechanism->mechanism) {
    case CKM_RSA_PKCS_OAEP:
      return RsaOaepEncrypter::New(key, mechanism);
    default:
      return InvalidMechanismError(mechanism->mechanism, "encrypt",
                                   SOURCE_LOCATION);
  }
}

StatusOr<SignOp> NewSignOp(std::shared_ptr<Object> key,
                           const CK_MECHANISM* mechanism) {
  switch (mechanism->mechanism) {
    case CKM_ECDSA:
      return EcdsaSigner::New(key, mechanism);
    case CKM_RSA_PKCS:
      return RsaPkcs1Signer::New(key, mechanism);
    case CKM_RSA_PKCS_PSS:
      return RsaPssSigner::New(key, mechanism);
    default:
      return InvalidMechanismError(mechanism->mechanism, "sign",
                                   SOURCE_LOCATION);
  }
}

StatusOr<VerifyOp> NewVerifyOp(std::shared_ptr<Object> key,
                               const CK_MECHANISM* mechanism) {
  switch (mechanism->mechanism) {
    case CKM_ECDSA:
      return EcdsaVerifier::New(key, mechanism);
    case CKM_RSA_PKCS:
      return RsaPkcs1Verifier::New(key, mechanism);
    default:
      return InvalidMechanismError(mechanism->mechanism, "verify",
                                   SOURCE_LOCATION);
  }
}

}  // namespace kmsp11