#include "platform.h"

void SetEnvVariable(const std::string& name, const std::string& value) {
  setenv(name.c_str(), value.c_str(), 1);
}

void ClearEnvVariable(const std::string& name) { unsetenv(name.c_str()); }
