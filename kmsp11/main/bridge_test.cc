#include "kmsp11/main/bridge.h"

#include <fstream>

#include "gmock/gmock.h"
#include "kmsp11/config/config.h"
#include "kmsp11/test/fakekms/cpp/fakekms.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/cleanup.h"
#include "kmsp11/util/platform.h"

namespace kmsp11 {
namespace {

namespace kms_v1 = ::google::cloud::kms::v1;

using ::testing::ElementsAre;

class BridgeTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_kms_, FakeKms::New());

    auto client = fake_kms_->NewClient();
    kms_v1::KeyRing kr1;
    kr1 = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr1);
    kms_v1::KeyRing kr2;
    kr2 = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr2);

    config_file_ = std::tmpnam(nullptr);
    std::ofstream(config_file_)
        << absl::StrFormat(R"(
tokens:
  - key_ring: "%s"
    label: "foo"
  - key_ring: "%s"
    label: "bar"
kms_endpoint: "%s"
use_insecure_grpc_channel_credentials: true
)",
                           kr1.name(), kr2.name(), fake_kms_->listen_addr());

    init_args_ = {0};
    init_args_.pReserved = const_cast<char*>(config_file_.c_str());
  }

  void TearDown() override { std::remove(config_file_.c_str()); }

  std::unique_ptr<FakeKms> fake_kms_;
  std::string config_file_;
  CK_C_INITIALIZE_ARGS init_args_;
};

TEST_F(BridgeTest, InitializeFromArgs) {
  EXPECT_OK(Initialize(&init_args_));
  EXPECT_OK(Finalize(nullptr));
}

TEST_F(BridgeTest, InitializeFailsOnSecondCall) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  EXPECT_THAT(Initialize(&init_args_),
              StatusRvIs(CKR_CRYPTOKI_ALREADY_INITIALIZED));
}

TEST_F(BridgeTest, InitializeFromEnvironment) {
  SetEnvVariable(kConfigEnvVariable, config_file_);
  Cleanup c([]() { ClearEnvVariable(kConfigEnvVariable); });

  EXPECT_OK(Initialize(nullptr));
  // Finalize so that other tests see an uninitialized state
  EXPECT_OK(Finalize(nullptr));
}

TEST_F(BridgeTest, InitArgsWithoutReservedLoadsFromEnv) {
  SetEnvVariable(kConfigEnvVariable, config_file_);
  Cleanup c([]() { ClearEnvVariable(kConfigEnvVariable); });

  CK_C_INITIALIZE_ARGS init_args = {0};
  EXPECT_OK(Initialize(&init_args));
  // Finalize so that other tests see an uninitialized state
  EXPECT_OK(Finalize(nullptr));
}

TEST_F(BridgeTest, InitializeFailsWithoutConfig) {
  EXPECT_THAT(Initialize(nullptr),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(BridgeTest, InitializeFailsWithArgsNoConfig) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  EXPECT_THAT(Initialize(&init_args),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(BridgeTest, FinalizeFailsWithoutInitialize) {
  EXPECT_THAT(Finalize(nullptr), StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, GetInfoSuccess) {
  EXPECT_OK(Initialize(&init_args_));
  CK_INFO info;
  EXPECT_OK(GetInfo(&info));
  EXPECT_OK(Finalize(nullptr));
}

TEST_F(BridgeTest, GetInfoFailsWithoutInitialize) {
  EXPECT_THAT(GetInfo(nullptr), StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, GetInfoFailsNullPtr) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  EXPECT_THAT(GetInfo(nullptr), StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST_F(BridgeTest, GetFunctionListSuccess) {
  CK_FUNCTION_LIST* function_list;
  EXPECT_OK(GetFunctionList(&function_list));
}

TEST_F(BridgeTest, FunctionListValidPointers) {
  CK_FUNCTION_LIST* f;
  EXPECT_OK(GetFunctionList(&f));

  EXPECT_EQ(f->C_Initialize(&init_args_), CKR_OK);
  CK_INFO info;
  EXPECT_EQ(f->C_GetInfo(&info), CKR_OK);
  EXPECT_EQ(f->C_Finalize(nullptr), CKR_OK);
}

TEST_F(BridgeTest, GetFunctionListFailsNullPtr) {
  EXPECT_THAT(GetFunctionList(nullptr), StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST_F(BridgeTest, GetSlotListFailsNotInitialized) {
  EXPECT_THAT(GetSlotList(false, nullptr, nullptr),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, GetSlotListReturnsSlots) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  std::vector<CK_SLOT_ID> slots(2);
  CK_ULONG slots_size = slots.size();
  EXPECT_OK(GetSlotList(false, slots.data(), &slots_size));
  EXPECT_EQ(slots_size, 2);
  EXPECT_THAT(slots, ElementsAre(0, 1));
}

TEST_F(BridgeTest, GetSlotListReturnsSize) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_ULONG slots_size;
  EXPECT_OK(GetSlotList(false, nullptr, &slots_size));
  EXPECT_EQ(slots_size, 2);
}

TEST_F(BridgeTest, GetSlotListFailsBufferTooSmall) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  std::vector<CK_SLOT_ID> slots(1);
  CK_ULONG slots_size = slots.size();
  EXPECT_THAT(GetSlotList(false, slots.data(), &slots_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(slots_size, 2);
}

TEST_F(BridgeTest, GetSlotInfoSuccess) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SLOT_INFO info;
  EXPECT_OK(GetSlotInfo(0, &info));

  // Sanity check for any piece of information we set
  EXPECT_EQ(info.flags & CKF_TOKEN_PRESENT, CKF_TOKEN_PRESENT);
}

TEST_F(BridgeTest, GetSlotInfoFailsNotInitialized) {
  EXPECT_THAT(GetSlotInfo(0, nullptr),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, GetSlotInfoFailsInvalidSlotId) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  EXPECT_THAT(GetSlotInfo(2, nullptr), StatusRvIs(CKR_SLOT_ID_INVALID));
}

TEST_F(BridgeTest, GetTokenInfoSuccess) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_TOKEN_INFO info;
  EXPECT_OK(GetTokenInfo(0, &info));

  // Sanity check for any piece of information we set
  EXPECT_EQ(info.flags & CKF_TOKEN_INITIALIZED, CKF_TOKEN_INITIALIZED);
}

TEST_F(BridgeTest, GetTokenInfoFailsNotInitialized) {
  EXPECT_THAT(GetTokenInfo(0, nullptr),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, GetTokenInfoFailsInvalidSlotId) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  EXPECT_THAT(GetTokenInfo(2, nullptr), StatusRvIs(CKR_SLOT_ID_INVALID));
}

TEST_F(BridgeTest, OpenSession) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));
  EXPECT_NE(handle, CK_INVALID_HANDLE);
}

TEST_F(BridgeTest, OpenSessionFailsNotInitialized) {
  CK_SESSION_HANDLE handle;
  EXPECT_THAT(OpenSession(0, 0, nullptr, nullptr, &handle),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, OpenSessionFailsInvalidSlotId) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle;
  EXPECT_THAT(OpenSession(2, CKF_SERIAL_SESSION, nullptr, nullptr, &handle),
              StatusRvIs(CKR_SLOT_ID_INVALID));
}

TEST_F(BridgeTest, OpenSessionFailsNotSerial) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle;
  EXPECT_THAT(OpenSession(0, 0, nullptr, nullptr, &handle),
              StatusRvIs(CKR_SESSION_PARALLEL_NOT_SUPPORTED));
}

TEST_F(BridgeTest, OpenSessionFailsReadWrite) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle;
  EXPECT_THAT(OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                          nullptr, &handle),
              StatusRvIs(CKR_TOKEN_WRITE_PROTECTED));
}

TEST_F(BridgeTest, CloseSessionSuccess) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));
  EXPECT_OK(CloseSession(handle));
}

TEST_F(BridgeTest, CloseSessionFailsNotInitialized) {
  EXPECT_THAT(CloseSession(0), StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, CloseSessionFailsInvalidHandle) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));
  EXPECT_THAT(CloseSession(0), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(BridgeTest, CloseSessionFailsAlreadyClosed) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));
  EXPECT_OK(CloseSession(handle));

  EXPECT_THAT(CloseSession(handle), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(BridgeTest, GetSessionInfoSuccess) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));

  CK_SESSION_INFO info;
  EXPECT_OK(GetSessionInfo(handle, &info));

  // Sanity check for any piece of information
  EXPECT_EQ(info.state, CKS_RO_PUBLIC_SESSION);
}

TEST_F(BridgeTest, GetSessionInfoFailsNotInitialized) {
  CK_SESSION_INFO info;
  EXPECT_THAT(GetSessionInfo(0, &info),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, GetSessionInfoFailsInvalidHandle) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_INFO info;
  EXPECT_THAT(GetSessionInfo(0, &info), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(BridgeTest, LoginSuccess) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));

  EXPECT_OK(Login(handle, CKU_USER, nullptr, 0));

  CK_SESSION_INFO info;
  EXPECT_OK(GetSessionInfo(handle, &info));
  EXPECT_EQ(info.state, CKS_RO_USER_FUNCTIONS);
}

TEST_F(BridgeTest, LoginAppliesToAllSessions) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle1;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle1));

  CK_SESSION_HANDLE handle2;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle2));

  EXPECT_OK(Login(handle2, CKU_USER, nullptr, 0));

  EXPECT_THAT(Login(handle1, CKU_USER, nullptr, 0),
              StatusRvIs(CKR_USER_ALREADY_LOGGED_IN));
  CK_SESSION_INFO info;
  EXPECT_OK(GetSessionInfo(handle1, &info));
  EXPECT_EQ(info.state, CKS_RO_USER_FUNCTIONS);
}

TEST_F(BridgeTest, LoginFailsNotInitialized) {
  EXPECT_THAT(Login(0, CKU_USER, nullptr, 0),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, LoginFailsInvalidHandle) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  EXPECT_THAT(Login(0, CKU_USER, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(BridgeTest, LoginFailsUserSo) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));

  EXPECT_THAT(Login(handle, CKU_SO, nullptr, 0), StatusRvIs(CKR_PIN_LOCKED));
}

TEST_F(BridgeTest, LogoutSuccess) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));

  EXPECT_OK(Login(handle, CKU_USER, nullptr, 0));
  EXPECT_OK(Logout(handle));

  CK_SESSION_INFO info;
  EXPECT_OK(GetSessionInfo(handle, &info));
  EXPECT_EQ(info.state, CKS_RO_PUBLIC_SESSION);
}

TEST_F(BridgeTest, LogoutAppliesToAllSessions) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle1;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle1));

  CK_SESSION_HANDLE handle2;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle2));

  EXPECT_OK(Login(handle2, CKU_USER, nullptr, 0));
  EXPECT_OK(Logout(handle1));

  EXPECT_THAT(Logout(handle2), StatusRvIs(CKR_USER_NOT_LOGGED_IN));
  CK_SESSION_INFO info;
  EXPECT_OK(GetSessionInfo(handle2, &info));
  EXPECT_EQ(info.state, CKS_RO_PUBLIC_SESSION);
}

TEST_F(BridgeTest, LogoutFailsNotInitialized) {
  EXPECT_THAT(Logout(0), StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, LogoutFailsInvalidHandle) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  EXPECT_THAT(Logout(0), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(BridgeTest, LogoutFailsNotLoggedIn) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));

  EXPECT_THAT(Logout(handle), StatusRvIs(CKR_USER_NOT_LOGGED_IN));
}

TEST_F(BridgeTest, LogoutFailsSecondCall) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));

  EXPECT_OK(Login(handle, CKU_USER, nullptr, 0));
  EXPECT_OK(Logout(handle));

  EXPECT_THAT(Logout(handle), StatusRvIs(CKR_USER_NOT_LOGGED_IN));
}

}  // namespace
}  // namespace kmsp11
