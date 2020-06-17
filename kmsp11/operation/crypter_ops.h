#ifndef KMSP11_OPERATION_CRYPTER_OPS_H_
#define KMSP11_OPERATION_CRYPTER_OPS_H_

#include "kmsp11/operation/crypter_interfaces.h"

namespace kmsp11 {

using DecryptOp = std::unique_ptr<DecrypterInterface>;

StatusOr<DecryptOp> NewDecryptOp(std::shared_ptr<Object> key,
                                 const CK_MECHANISM* mechanism);

using EncryptOp = std::unique_ptr<EncrypterInterface>;

StatusOr<EncryptOp> NewEncryptOp(std::shared_ptr<Object> key,
                                 const CK_MECHANISM* mechanism);

using SignOp = std::unique_ptr<SignerInterface>;

StatusOr<SignOp> NewSignOp(std::shared_ptr<Object> key,
                           const CK_MECHANISM* mechanism);

using VerifyOp = std::unique_ptr<VerifierInterface>;

StatusOr<VerifyOp> NewVerifyOp(std::shared_ptr<Object> key,
                               const CK_MECHANISM* mechanism);

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_CRYPTER_OPS_H_
