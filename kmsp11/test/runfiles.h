#ifndef KMSP11_TEST_RUNFILES_H_
#define KMSP11_TEST_RUNFILES_H_

#include <string>

#include "kmsp11/util/status_or.h"

namespace kmsp11 {

// Resolves the absolute location of the provided runfile.
std::string RunfileLocation(absl::string_view filename);

// Loads the testdata file with the provided filename into a string.
StatusOr<std::string> LoadTestRunfile(absl::string_view filename);

}  // namespace kmsp11

#endif  // KMSP11_TEST_RUNFILES_H_
