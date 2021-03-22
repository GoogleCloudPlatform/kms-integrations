#include <fstream>

#include "absl/cleanup/cleanup.h"
#include "gmock/gmock.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/main/bridge.h"
#include "kmsp11/test/fakekms/cpp/fakekms.h"
#include "kmsp11/test/test_status_macros.h"

namespace kmsp11 {
namespace {

TEST(FipsTest, InitializePassesFipsSelfTestFipsModeRequired) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeKms> fake_kms, FakeKms::New());

  std::string config_file = std::tmpnam(nullptr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << absl::StrFormat(R"(
kms_endpoint: %s
use_insecure_grpc_channel_credentials: true
experimental_require_fips_mode: true
)",
                         fake_kms->listen_addr());
  absl::Cleanup c = [&] { std::remove(config_file.c_str()); };

  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.flags = CKF_OS_LOCKING_OK;
  init_args.pReserved = const_cast<char*>(config_file.c_str());

  EXPECT_OK(Initialize(&init_args));
  EXPECT_OK(Finalize(nullptr));
}

}  // namespace
}  // namespace kmsp11