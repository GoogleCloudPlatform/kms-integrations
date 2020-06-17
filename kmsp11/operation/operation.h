#ifndef KMSP11_OPERATION_OPERATION_H_
#define KMSP11_OPERATION_OPERATION_H_

#include "absl/types/variant.h"
#include "kmsp11/operation/crypter_ops.h"
#include "kmsp11/operation/find.h"

namespace kmsp11 {

// Operation models an in progress stateful PKCS #11 operation.
using Operation = absl::variant<FindOp, DecryptOp, EncryptOp, SignOp, VerifyOp>;

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_OPERATION_H_
