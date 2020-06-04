#ifndef KMSP11_MECHANISM_H_
#define KMSP11_MECHANISM_H_

#include "absl/types/span.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/util/status_or.h"

namespace kmsp11 {

// Returns a sorted list of the mechanism types supported in this library.
absl::Span<const CK_MECHANISM_TYPE> Mechanisms();

// Returns details about the provided mechanism type.
StatusOr<CK_MECHANISM_INFO> MechanismInfo(CK_MECHANISM_TYPE type);

}  // namespace kmsp11

#endif  // KMSP11_MECHANISM_H_
