#ifndef KMSP11_UTIL_STATUS_MACROS_H_
#define KMSP11_UTIL_STATUS_MACROS_H_

#include "kmsp11/util/status_utils.h"

// Run a command that returns an absl::Status. If the called code returns a
// non-OK status, return that value up out of this method too.
//
// Example:
//   RETURN_IF_ERROR(DoThings(4));
#define RETURN_IF_ERROR(expr)                                                \
  do {                                                                       \
    /* Using _status below to avoid capture problems if expr is "status". */ \
    const ::absl::Status _status = ::kmsp11::ToStatus(expr);                 \
    if (!_status.ok()) return _status;                                       \
  } while (0)

// Internal helper for concatenating macro values.
#define STATUS_CONCAT_NAME_INNER(x, y) x##y
#define STATUS_CONCAT_NAME(x, y) STATUS_CONCAT_NAME_INNER(x, y)

#define ASSIGN_OR_RETURN_IMPL(var, lhs, rexpr)                                \
  auto var = (rexpr);                                                         \
  if (ABSL_PREDICT_FALSE(!var.ok())) return ::kmsp11::ToStatus(var.status()); \
  lhs = std::move(var).value();

// Executes an expression that returns a absl::StatusOr, extracting its value
// into the variable defined by lhs (or returning on error).
//
// Example: Assigning to an existing value
//   ValueType value;
//   ASSIGN_OR_RETURN(value, MaybeGetValue(arg));
//
// WARNING: ASSIGN_OR_RETURN expands into multiple statements; it cannot be used
//  in a single statement (e.g. as the body of an if statement without {})!
#define ASSIGN_OR_RETURN(lhs, rexpr)                                      \
  ASSIGN_OR_RETURN_IMPL(STATUS_CONCAT_NAME(_status_or, __COUNTER__), lhs, \
                        rexpr);

#endif  // KMSP11_UTIL_STATUS_MACROS_H_
