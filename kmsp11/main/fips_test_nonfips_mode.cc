#include <fstream>

#include "absl/cleanup/cleanup.h"
#include "gmock/gmock.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/main/bridge.h"

namespace kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::HasSubstr;

TEST(FipsTest, InitializeFailsFipsSelfTestFipsModeRequired) {
  std::string config_file = std::tmpnam(nullptr);
  std::ofstream(config_file)
      << "experimental_require_fips_mode: true" << std::endl;
  absl::Cleanup c = [&] { std::remove(config_file.c_str()); };

  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.flags = CKF_OS_LOCKING_OK;
  init_args.pReserved = const_cast<char*>(config_file.c_str());

  EXPECT_DEATH(
      Initialize(&init_args).IgnoreError(),
      AllOf(HasSubstr("FIPS tests failed"), HasSubstr("FIPS_mode()=0")));
}

}  // namespace
}  // namespace kmsp11
