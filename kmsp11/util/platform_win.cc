#include "platform.h"

void SetEnvVariable(const std::string& name, const std::string& value) {
  _putenv_s(name.c_str(), value.c_str());
}

void ClearEnvVariable(const std::string& name) { _putenv_s(name.c_str(), ""); }