// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
