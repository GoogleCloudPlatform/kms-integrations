#ifndef KMSP11_OPERATION_MECHANISM_PRECONDITIONS_H_
#define KMSP11_OPERATION_MECHANISM_PRECONDITIONS_H_

#include "absl/status/status.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/object.h"

namespace kmsp11 {

// Ensures that object is consistent with the specified key_type,
// mechanism_type, and object_class, or returns an appropriate error.
absl::Status CheckKeyPreconditions(CK_KEY_TYPE key_type,
                                   CK_OBJECT_CLASS object_class,
                                   CK_MECHANISM_TYPE mechanism_type,
                                   Object* object);

// Returns InvalidArgument if the provided mechanism contains parameters.
absl::Status EnsureNoParameters(const CK_MECHANISM* mechanism);

// Ensure that the provided mechanism matches the expected hash algorithm.
absl::Status EnsureHashMatches(CK_MECHANISM_TYPE actual,
                               const EVP_MD* expected);

// Ensure that the provided MGF type is MGF-1 with the expected hash
// algorithm.
absl::Status EnsureMgf1HashMatches(CK_RSA_PKCS_MGF_TYPE actual,
                                   const EVP_MD* expected);

}  // namespace kmsp11

#endif  // KMSP11_OPERATION_MECHANISM_PRECONDITIONS_H_
