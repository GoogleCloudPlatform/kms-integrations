#ifndef KMSP11_UTIL_PLATFORM_H_
#define KMSP11_UTIL_PLATFORM_H_

#include <cstdlib>
#include <string>

// Set the named environment variable to the provided value, replacing any
// existing value.
void SetEnvVariable(const std::string& name, const std::string& value);

// Remove the named variable from the environment, if it exists.
void ClearEnvVariable(const std::string& name);

#endif  // KMSP11_UTIL_PLATFORM_H_
