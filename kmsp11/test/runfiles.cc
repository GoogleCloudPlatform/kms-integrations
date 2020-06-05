#include "kmsp11/test/runfiles.h"

#include "absl/base/call_once.h"
#include "gtest/gtest.h"
#include "tools/cpp/runfiles/runfiles.h"

namespace kmsp11 {
namespace {

using ::bazel::tools::cpp::runfiles::Runfiles;

static absl::once_flag runfiles_once;
static Runfiles* runfiles;

void LoadRunfiles() {
  std::string error;
  runfiles = Runfiles::CreateForTest(&error);
  ASSERT_TRUE(runfiles) << "error creating runfiles: " << error;
}

Runfiles* GetRunfiles() {
  absl::call_once(runfiles_once, &LoadRunfiles);
  return runfiles;
}

}  // namespace

std::string RunfileLocation(const std::string& runfile_path) {
  return GetRunfiles()->Rlocation(runfile_path);
}

}  // namespace kmsp11
