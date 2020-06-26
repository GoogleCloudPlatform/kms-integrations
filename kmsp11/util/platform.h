#ifndef KMSP11_UTIL_PLATFORM_H_
#define KMSP11_UTIL_PLATFORM_H_

#include <cstdlib>
#include <string>

#include "absl/status/status.h"

namespace kmsp11 {

// Set the named environment variable to the provided value, replacing any
// existing value.
void SetEnvVariable(const char* name, const char* value);

// Set the named environment variable to the provided value, replacing any
// existing value.
inline void SetEnvVariable(const std::string& name, const std::string& value) {
  return SetEnvVariable(name.c_str(), value.c_str());
}

// Remove the named variable from the environment, if it exists.
void ClearEnvVariable(const char* name);

// Remove the named variable from the environment, if it exists.
inline void ClearEnvVariable(const std::string& name) {
  ClearEnvVariable(name.c_str());
}

// Ensure that the file at the provided path is not group- or world- writeable.
// Note that always returns OK on Windows. (See b/148377771).
// TODO(bdhess): move to C++17 filesystem module for Beta
absl::Status EnsureWriteProtected(const char* filename);

// Set the file mode at the provided path. Note that this always returns
// Unimplemented on Windows.
absl::Status SetMode(const char* filename, int mode);

}  // namespace kmsp11

#endif  // KMSP11_UTIL_PLATFORM_H_
