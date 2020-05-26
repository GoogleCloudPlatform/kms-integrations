#ifndef KMSP11_UTIL_PLATFORM_H_
#define KMSP11_UTIL_PLATFORM_H_

#include <cstdlib>
#include <string>

#include "absl/status/status.h"

// Set the named environment variable to the provided value, replacing any
// existing value.
void SetEnvVariable(const std::string& name, const std::string& value);

// Remove the named variable from the environment, if it exists.
void ClearEnvVariable(const std::string& name);

// Ensure that the file at the provided path is not group- or world- writeable.
// Note that always returns OK on Windows. (See b/148377771).
// TODO(bdhess): move to C++17 filesystem module for Beta
absl::Status EnsureWriteProtected(const char* filename);

// Set the file mode at the provided path. Note that this always returns
// Unimplemented on Windows.
absl::Status SetMode(const char* filename, int mode);

#endif  // KMSP11_UTIL_PLATFORM_H_
