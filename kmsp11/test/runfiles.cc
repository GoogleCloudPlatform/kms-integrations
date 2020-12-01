#include "kmsp11/test/runfiles.h"

#include <fstream>

#include "absl/strings/str_cat.h"
#include "glog/logging.h"
#include "gtest/gtest.h"
#include "tools/cpp/runfiles/runfiles.h"

namespace kmsp11 {
namespace {

using ::bazel::tools::cpp::runfiles::Runfiles;

Runfiles* GetRunfiles() {
  static Runfiles* runfiles = [] {
    std::string error;
    Runfiles* runfiles = Runfiles::CreateForTest(&error);
    CHECK(runfiles != nullptr) << "error creating runfiles: " << error;
    return runfiles;
  }();
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
