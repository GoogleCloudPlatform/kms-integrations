#include <sys/wait.h>

#include <fstream>

#include "absl/cleanup/cleanup.h"
#include "fakekms/cpp/fakekms.h"
#include "gmock/gmock.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/main/bridge.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/platform.h"

namespace kmsp11 {
namespace {

// Forking isn't officially supported by gRPC, but it seems to mostly work, so
// we should try to get them to support it for us if feasible. Until then, this
// test ensures we don't introduce a regression that breaks forking.
TEST(ForkTest, ProviderToleratesForkAfterInitWithEnvVariableSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeKms> fake_kms, FakeKms::New());
  auto client = fake_kms->NewClient();

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr);

  std::string config_file = std::tmpnam(nullptr);
  std::ofstream(config_file)
      << absl::StrFormat(R"(
tokens:
  - key_ring: "%s"
kms_endpoint: "%s"
use_insecure_grpc_channel_credentials: true
refresh_interval_secs: 0
)",
                         kr.name(), fake_kms->listen_addr());
  absl::Cleanup c1 = [&] { std::remove(config_file.c_str()); };

  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.flags = CKF_OS_LOCKING_OK;
  init_args.pReserved = const_cast<char*>(config_file.c_str());

  // This magic env variable is needed for gRPC to include fork support.
  std::string grpc_fork_env_var = "GRPC_ENABLE_FORK_SUPPORT";
  SetEnvVariable(grpc_fork_env_var, "1");
  absl::Cleanup c2 = [&] { ClearEnvVariable(grpc_fork_env_var); };

  ASSERT_OK(Initialize(&init_args));
  absl::Cleanup c3 = [] { ASSERT_OK(Finalize(nullptr)); };

  pid_t pid = fork();
  switch (pid) {
    // fork failure
    case -1: {
      FAIL() << "Failure forking.";
    }

    // post-fork child
    case 0: {
      absl::Status init_result = Initialize(&init_args);
      // Assertions made post-fork won't get logged; CHECK-failing dumps to
      // stderr so /will/ get picked up in the test log.
      CHECK(init_result.ok()) << init_result;
      exit(0);
    }

    // post-fork parent
    default: {
      int exit_code;
      ASSERT_EQ(waitpid(pid, &exit_code, 0), pid)
          << "failure waiting for child process: " << errno;
      EXPECT_EQ(exit_code, 0);
    }
  }
}

}  // namespace
}  // namespace kmsp11