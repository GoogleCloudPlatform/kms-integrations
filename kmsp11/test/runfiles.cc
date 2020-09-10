#include "kmsp11/test/runfiles.h"

#include <fstream>

#include "absl/base/call_once.h"
#include "absl/strings/str_cat.h"
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

std::string RunfileLocation(absl::string_view filename) {
  return GetRunfiles()->Rlocation(std::string(filename));
}

absl::StatusOr<std::string> LoadTestRunfile(absl::string_view filename) {
  std::string location = RunfileLocation(
      absl::StrCat("com_google_kmstools/kmsp11/test/testdata/", filename));
  std::ifstream runfile(location, std::ifstream::in | std::ifstream::binary);
  return std::string((std::istreambuf_iterator<char>(runfile)),
                     (std::istreambuf_iterator<char>()));
}

}  // namespace kmsp11
