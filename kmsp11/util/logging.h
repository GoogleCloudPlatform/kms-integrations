#ifndef KMSP11_UTIL_LOGGING_H_
#define KMSP11_UTIL_LOGGING_H_

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "kmsp11/cryptoki.h"

namespace kmsp11 {

absl::Status InitializeLogging(absl::string_view output_directory,
                               absl::string_view output_filename_suffix);
void ShutdownLogging();

CK_RV LogAndResolve(absl::string_view function_name,
                    const absl::Status& status);

}  // namespace kmsp11

#endif  // KMSP11_UTIL_LOGGING_H_
