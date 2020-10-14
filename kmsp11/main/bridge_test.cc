#include "kmsp11/main/bridge.h"

#include <fstream>

#include "gmock/gmock.h"
#include "kmsp11/config/config.h"
#include "kmsp11/test/fakekms/cpp/fakekms.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/cleanup.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/platform.h"
#include "openssl/rand.h"
#include "openssl/sha.h"

namespace kmsp11 {
namespace {

using ::testing::AnyOf;
using ::testing::ElementsAre;
using ::testing::Ge;
using ::testing::HasSubstr;
using ::testing::IsSupersetOf;

class BridgeTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_kms_, FakeKms::New());

    auto client = fake_kms_->NewClient();
    kr1_ = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr1_);
    kr2_ = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr2_);

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
                           kr1_.name(), kr2_.name(), fake_kms_->listen_addr());

    init_args_ = {0};
    init_args_.flags = CKF_OS_LOCKING_OK;
    init_args_.pReserved = const_cast<char*>(config_file_.c_str());
  }

  void TearDown() override { std::remove(config_file_.c_str()); }

  std::unique_ptr<FakeKms> fake_kms_;
  kms_v1::KeyRing kr1_;
  kms_v1::KeyRing kr2_;
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
  init_args.flags = CKF_OS_LOCKING_OK;
  EXPECT_OK(Initialize(&init_args));
  // Finalize so that other tests see an uninitialized state
  EXPECT_OK(Finalize(nullptr));
}

TEST_F(BridgeTest, InitializeFailsWithoutConfig) {
  EXPECT_THAT(Initialize(nullptr),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(BridgeTest, InitializeFailsWithArgsNoOsLocking) {
  CK_C_INITIALIZE_ARGS init_args = {0};

  EXPECT_THAT(Initialize(&init_args), StatusRvIs(CKR_CANT_LOCK));
}

TEST_F(BridgeTest, InitializeFailsWithArgsNoThreads) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.flags = CKF_OS_LOCKING_OK | CKF_LIBRARY_CANT_CREATE_OS_THREADS;

  EXPECT_THAT(Initialize(&init_args), StatusRvIs(CKR_NEED_TO_CREATE_THREADS));
}

TEST_F(BridgeTest, InitializeFailsWithArgsNoConfig) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.flags = CKF_OS_LOCKING_OK;

  EXPECT_THAT(Initialize(&init_args),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       HasSubstr("cannot load configuration")));
}

TEST_F(BridgeTest, InitializationWarningsAreLogged) {
  // Create a key that will be skipped at init time (purpose==ENCRYPT_DECRYPT)
  auto fake_client = fake_kms_->NewClient();
  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);
  ck.mutable_version_template()->set_protection_level(kms_v1::HSM);
  ck = CreateCryptoKeyOrDie(fake_client.get(), kr1_.name(), "ck", ck, true);

  // TODO(b/160310720): Remove the use of gtest internals when we move to C++17.
  testing::internal::CaptureStderr();

  ASSERT_OK(Initialize(&init_args_));
  ASSERT_OK(Finalize(nullptr));

  EXPECT_THAT(testing::internal::GetCapturedStderr(),
              HasSubstr("unsupported purpose"));
}

TEST_F(BridgeTest, LoggingIsInitializedBeforeKmsCallsAreMade) {
  // Create a key that will be skipped at init time (purpose==ENCRYPT_DECRYPT)
  auto fake_client = fake_kms_->NewClient();
  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);
  ck.mutable_version_template()->set_protection_level(kms_v1::HSM);
  ck = CreateCryptoKeyOrDie(fake_client.get(), kr1_.name(), "ck", ck, true);

  // TODO(b/160310720): Remove the use of gtest internals when we move to C++17.
  testing::internal::CaptureStderr();

  ASSERT_OK(Initialize(&init_args_));
  ASSERT_OK(Finalize(nullptr));

  EXPECT_THAT(testing::internal::GetCapturedStderr(),
              Not(HasSubstr("WARNING: Logging before InitGoogleLogging()")));
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

TEST_F(BridgeTest, OpenSessionReadWrite) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                        nullptr, &handle));

  CK_SESSION_INFO info;
  EXPECT_OK(GetSessionInfo(handle, &info));

  EXPECT_EQ(info.state, CKS_RW_PUBLIC_SESSION);
  EXPECT_EQ(info.flags & CKF_RW_SESSION, CKF_RW_SESSION);
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

TEST_F(BridgeTest, GetMechanismListSucceeds) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_ULONG count;
  EXPECT_OK(GetMechanismList(0, nullptr, &count));

  std::vector<CK_MECHANISM_TYPE> types(count);
  EXPECT_OK(GetMechanismList(0, types.data(), &count));
  EXPECT_EQ(types.size(), count);
  EXPECT_THAT(types, IsSupersetOf({CKM_RSA_PKCS, CKM_RSA_PKCS_PSS,
                                   CKM_RSA_PKCS_OAEP, CKM_ECDSA}));
}

TEST_F(BridgeTest, GetMechanismListFailsInvalidSize) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  std::vector<CK_MECHANISM_TYPE> types(1);
  CK_ULONG count = 1;
  EXPECT_THAT(GetMechanismList(0, types.data(), &count),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_THAT(count, Ge(4));
}

TEST_F(BridgeTest, GetMechanismListFailsNotInitialized) {
  CK_ULONG count;
  EXPECT_THAT(GetMechanismList(0, nullptr, &count),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, GetMechanismListFailsInvalidSlotId) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_ULONG count;
  EXPECT_THAT(GetMechanismList(5, nullptr, &count),
              StatusRvIs(CKR_SLOT_ID_INVALID));
}

TEST_F(BridgeTest, GetMechanismInfo) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_MECHANISM_INFO info;
  EXPECT_OK(GetMechanismInfo(0, CKM_RSA_PKCS_PSS, &info));

  EXPECT_EQ(info.ulMinKeySize, 2048);
  EXPECT_EQ(info.ulMaxKeySize, 4096);
  EXPECT_EQ(info.flags, CKF_SIGN | CKF_VERIFY);
}

TEST_F(BridgeTest, GetMechanismInfoFailsInvalidMechanism) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_MECHANISM_INFO info;
  EXPECT_THAT(GetMechanismInfo(0, CKM_RSA_X9_31, &info),
              StatusRvIs(CKR_MECHANISM_INVALID));
}

TEST_F(BridgeTest, GetMechanismInfoFailsNotInitialized) {
  CK_MECHANISM_INFO info;
  EXPECT_THAT(GetMechanismInfo(0, CKM_RSA_PKCS, &info),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, GetMechanismInfoFailsInvalidSlotId) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_MECHANISM_INFO info;
  EXPECT_THAT(GetMechanismInfo(5, CKM_RSA_PKCS_PSS, &info),
              StatusRvIs(CKR_SLOT_ID_INVALID));
}

TEST_F(BridgeTest, GetAttributeValueSuccess) {
  auto fake_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(fake_client.get(), kr1_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv1;
  ckv1 = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv1);
  ckv1 = WaitForEnablement(fake_client.get(), ckv1);

  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attr_template = {CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1));

  CK_OBJECT_HANDLE object;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &object, 1, &found_count));
  EXPECT_EQ(found_count, 1);

  CK_KEY_TYPE key_type;
  CK_ATTRIBUTE key_type_attr = {CKA_KEY_TYPE, &key_type, sizeof(key_type)};
  EXPECT_OK(GetAttributeValue(session, object, &key_type_attr, 1));
  EXPECT_EQ(key_type, CKK_EC);
}

TEST_F(BridgeTest, GetAttributeValueFailsSensitiveAttribute) {
  auto fake_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(fake_client.get(), kr1_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv1;
  ckv1 = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv1);
  ckv1 = WaitForEnablement(fake_client.get(), ckv1);

  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attr_template = {CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1));

  CK_OBJECT_HANDLE object;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &object, 1, &found_count));
  EXPECT_EQ(found_count, 1);

  char key_value[256];
  CK_ATTRIBUTE value_attr = {CKA_VALUE, key_value, 256};
  EXPECT_THAT(GetAttributeValue(session, object, &value_attr, 1),
              StatusRvIs(CKR_ATTRIBUTE_SENSITIVE));
  EXPECT_EQ(value_attr.ulValueLen, CK_UNAVAILABLE_INFORMATION);
}

TEST_F(BridgeTest, GetAttributeValueFailsNonExistentAttribute) {
  auto fake_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(fake_client.get(), kr1_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv1;
  ckv1 = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv1);
  ckv1 = WaitForEnablement(fake_client.get(), ckv1);

  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attr_template = {CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1));

  CK_OBJECT_HANDLE object;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &object, 1, &found_count));
  EXPECT_EQ(found_count, 1);

  char modulus[256];
  CK_ATTRIBUTE mod_attr = {CKA_MODULUS, modulus, 256};
  EXPECT_THAT(GetAttributeValue(session, object, &mod_attr, 1),
              StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));
  EXPECT_EQ(mod_attr.ulValueLen, CK_UNAVAILABLE_INFORMATION);
}

TEST_F(BridgeTest, GetAttributeValueSuccessNoBuffer) {
  auto fake_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(fake_client.get(), kr1_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv1;
  ckv1 = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv1);
  ckv1 = WaitForEnablement(fake_client.get(), ckv1);

  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attr_template = {CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1))

  CK_OBJECT_HANDLE object;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &object, 1, &found_count));
  EXPECT_EQ(found_count, 1);

  CK_ATTRIBUTE public_key = {CKA_PUBLIC_KEY_INFO, nullptr, 0};
  EXPECT_OK(GetAttributeValue(session, object, &public_key, 1));
}

TEST_F(BridgeTest, GetAttributeValueFailureBufferTooShort) {
  auto fake_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(fake_client.get(), kr1_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv1;
  ckv1 = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv1);
  ckv1 = WaitForEnablement(fake_client.get(), ckv1);

  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attr_template = {CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1))

  CK_OBJECT_HANDLE object;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &object, 1, &found_count));
  EXPECT_EQ(found_count, 1);

  char buf[2];
  CK_ATTRIBUTE ec_params = {CKA_EC_PARAMS, buf, 2};
  EXPECT_THAT(GetAttributeValue(session, object, &ec_params, 1),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_GT(ec_params.ulValueLen, 2);
}

TEST_F(BridgeTest, GetAttributeValueFailureAllAttributesProcessed) {
  auto fake_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(fake_client.get(), kr1_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv1;
  ckv1 = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv1);
  ckv1 = WaitForEnablement(fake_client.get(), ckv1);

  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attr_template = {CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1))

  CK_OBJECT_HANDLE object;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &object, 1, &found_count));
  EXPECT_EQ(found_count, 1);

  CK_BBOOL decrypt, token;
  char value_buf[2], point_buf[2], modulus_buf[2];
  CK_ATTRIBUTE attr_results[5] = {
      {CKA_DECRYPT, &decrypt, sizeof(decrypt)},
      {CKA_VALUE, value_buf, sizeof(value_buf)},
      {CKA_EC_POINT, point_buf, sizeof(point_buf)},
      {CKA_MODULUS, modulus_buf, sizeof(modulus_buf)},
      {CKA_TOKEN, &token, sizeof(token)},
  };

  EXPECT_THAT(GetAttributeValue(session, object, attr_results, 5),
              StatusRvIs(AnyOf(CKR_BUFFER_TOO_SMALL, CKR_ATTRIBUTE_SENSITIVE,
                               CKR_ATTRIBUTE_TYPE_INVALID)));

  // All valid attributes with sufficient buffer space were processed.
  EXPECT_EQ(decrypt, CK_FALSE);
  EXPECT_EQ(attr_results[0].ulValueLen, 1);
  EXPECT_EQ(token, CK_TRUE);
  EXPECT_EQ(attr_results[4].ulValueLen, 1);

  // Sensitive attribute is unavailable.
  EXPECT_EQ(attr_results[1].ulValueLen, CK_UNAVAILABLE_INFORMATION);
  // Buffer too small attribute is unavailable.
  EXPECT_THAT(attr_results[2].ulValueLen, CK_UNAVAILABLE_INFORMATION);
  // Not found attribute is unavailable.
  EXPECT_EQ(attr_results[3].ulValueLen, CK_UNAVAILABLE_INFORMATION);
}

TEST_F(BridgeTest, GetAttributeValueFailureNotInitialized) {
  EXPECT_THAT(GetAttributeValue(0, 0, nullptr, 0),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, GetAttributeValueFailureInvalidSessionHandle) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  EXPECT_THAT(GetAttributeValue(0, 0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(BridgeTest, GetAttributeValueFailureInvalidObjectHandle) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_THAT(GetAttributeValue(session, 0, nullptr, 0),
              StatusRvIs(CKR_OBJECT_HANDLE_INVALID));
}

TEST_F(BridgeTest, GetAttributeValueFailureNullTemplate) {
  auto fake_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(fake_client.get(), kr1_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv1;
  ckv1 = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv1);
  ckv1 = WaitForEnablement(fake_client.get(), ckv1);

  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attr_template = {CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1))

  CK_OBJECT_HANDLE object;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &object, 1, &found_count));
  EXPECT_EQ(found_count, 1);

  EXPECT_THAT(GetAttributeValue(session, object, nullptr, 1),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST_F(BridgeTest, FindEcPrivateKey) {
  auto fake_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(fake_client.get(), kr1_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(fake_client.get(), ckv);

  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_KEY_TYPE key_type = CKK_EC;
  std::vector<CK_ATTRIBUTE> attrs({
      {CKA_CLASS, &obj_class, sizeof(obj_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
  });
  EXPECT_OK(FindObjectsInit(session, &attrs[0], attrs.size()));

  CK_OBJECT_HANDLE handles[2];
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &handles[0], 2, &found_count));
  EXPECT_EQ(found_count, 1);

  char label[2];
  std::vector<CK_ATTRIBUTE> found_attrs({
      {CKA_CLASS, &obj_class, sizeof(obj_class)},
      {CKA_LABEL, label, 2},
  });
  EXPECT_OK(GetAttributeValue(session, handles[0], found_attrs.data(), 2));

  EXPECT_EQ(obj_class, CKO_PRIVATE_KEY);
  EXPECT_EQ(std::string(label, 2), "ck");

  EXPECT_OK(FindObjectsFinal(session));
}

TEST_F(BridgeTest, FindCertificate) {
  auto fake_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(fake_client.get(), kr1_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(fake_client.get(), ckv);

  std::ofstream(config_file_, std::ofstream::out | std::ofstream::app)
      << "generate_certs: true" << std::endl;

  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_CERTIFICATE;
  CK_ATTRIBUTE attr_template{CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1));

  CK_OBJECT_HANDLE handles[2];
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &handles[0], 2, &found_count));
  EXPECT_EQ(found_count, 1);
}

TEST_F(BridgeTest, NoCertificatesWhenConfigNotSet) {
  auto fake_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(fake_client.get(), kr1_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(fake_client.get(), ckv);

  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_CERTIFICATE;
  CK_ATTRIBUTE attr_template{CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1));

  CK_OBJECT_HANDLE handle;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &handle, 1, &found_count));
  EXPECT_EQ(found_count, 0);
}

TEST_F(BridgeTest, FindObjectsInitSuccess) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));
}

TEST_F(BridgeTest, FindObjectsInitFailsNotInitialized) {
  EXPECT_THAT(FindObjectsInit(0, nullptr, 0),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, FindObjectsInitFailsInvalidSessionHandle) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  EXPECT_THAT(FindObjectsInit(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(BridgeTest, FindObjectsInitFailsAttributeTemplateNullptr) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_THAT(FindObjectsInit(session, nullptr, 1),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST_F(BridgeTest, FindObjectsInitFailsAlreadyInitialized) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));
  EXPECT_THAT(FindObjectsInit(session, nullptr, 0),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(BridgeTest, FindObjectsSuccess) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));

  CK_OBJECT_HANDLE handle;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &handle, 1, &found_count));
  EXPECT_EQ(found_count, 0);
}

TEST_F(BridgeTest, FindObjectsFailsNotInitialized) {
  EXPECT_THAT(FindObjects(0, nullptr, 0, nullptr),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, FindObjectsFailsInvalidSessionHandle) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  EXPECT_THAT(FindObjects(0, nullptr, 0, nullptr),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(BridgeTest, FindObjectsFailsPhObjectNull) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));

  CK_ULONG found_count;
  EXPECT_THAT(FindObjects(session, nullptr, 0, &found_count),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST_F(BridgeTest, FindObjectsFailsPulCountNull) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));

  CK_OBJECT_HANDLE handles[1];
  EXPECT_THAT(FindObjects(session, &handles[0], 1, nullptr),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST_F(BridgeTest, FindObjectsFailsOperationNotInitialized) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_HANDLE obj_handle;
  CK_ULONG found_count;
  EXPECT_THAT(FindObjects(session, &obj_handle, 1, &found_count),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(BridgeTest, FindObjectsFinalSuccess) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));
  EXPECT_OK(FindObjectsFinal(session));
}

TEST_F(BridgeTest, FindObjectsFinalFailsNotInitialized) {
  EXPECT_THAT(FindObjectsFinal(0), StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST_F(BridgeTest, FindObjectsFinalFailsInvalidSessionHandle) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  EXPECT_THAT(FindObjectsFinal(0), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(BridgeTest, FindObjectsFinalFailsOperationNotInitialized) {
  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_THAT(FindObjectsFinal(session),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(BridgeTest, FindObjectsContainsNewResultsAfterRefresh) {
  std::ofstream(config_file_, std::ofstream::out | std::ofstream::app)
      << "refresh_interval_secs: 1" << std::endl;

  EXPECT_OK(Initialize(&init_args_));
  Cleanup c([]() { EXPECT_OK(Finalize(nullptr)); });

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));
  CK_ULONG found_count;
  std::vector<CK_OBJECT_HANDLE> objects(2);
  EXPECT_OK(FindObjects(session, objects.data(), objects.size(), &found_count));
  EXPECT_EQ(found_count, 0);
  EXPECT_OK(FindObjectsFinal(session));

  auto fake_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(fake_client.get(), kr1_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(fake_client.get(), ckv);

  absl::SleepFor(absl::Seconds(2));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));
  EXPECT_OK(FindObjects(session, objects.data(), objects.size(), &found_count));
  EXPECT_EQ(found_count, 2);
  EXPECT_OK(FindObjectsFinal(session));
}

class AsymmetricCryptTest : public BridgeTest {
 protected:
  void SetUp() override {
    BridgeTest::SetUp();
    auto kms_client = fake_kms_->NewClient();

    kms_v1::CryptoKey ck;
    ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
    ck.mutable_version_template()->set_algorithm(
        kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
    ck.mutable_version_template()->set_protection_level(
        kms_v1::ProtectionLevel::HSM);
    ck = CreateCryptoKeyOrDie(kms_client.get(), kr1_.name(), "ck", ck, true);

    kms_v1::CryptoKeyVersion ckv;
    ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
    ckv = WaitForEnablement(kms_client.get(), ckv);

    kms_v1::PublicKey pub_proto = GetPublicKey(kms_client.get(), ckv);
    ASSERT_OK_AND_ASSIGN(pub_pkey_, ParseX509PublicKeyPem(pub_proto.pem()));

    EXPECT_OK(Initialize(&init_args_));
    EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session_));

    CK_OBJECT_CLASS object_class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE attr_template[2] = {
        {CKA_ID, const_cast<char*>(ckv.name().data()), ckv.name().size()},
        {CKA_CLASS, &object_class, sizeof(object_class)},
    };
    CK_ULONG found_count;

    EXPECT_OK(FindObjectsInit(session_, attr_template, 2));
    EXPECT_OK(FindObjects(session_, &private_key_, 1, &found_count));
    EXPECT_EQ(found_count, 1);
    EXPECT_OK(FindObjectsFinal(session_));

    object_class = CKO_PUBLIC_KEY;
    EXPECT_OK(FindObjectsInit(session_, attr_template, 2));
    EXPECT_OK(FindObjects(session_, &public_key_, 1, &found_count));
    EXPECT_EQ(found_count, 1);
    EXPECT_OK(FindObjectsFinal(session_))
  }

  void TearDown() override { EXPECT_OK(Finalize(nullptr)); }

  CK_SESSION_HANDLE session_;
  CK_OBJECT_HANDLE private_key_;
  CK_OBJECT_HANDLE public_key_;
  bssl::UniquePtr<EVP_PKEY> pub_pkey_;
};

TEST_F(AsymmetricCryptTest, DecryptSuccess) {
  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  uint8_t ciphertext[256];
  EXPECT_OK(EncryptRsaOaep(pub_pkey_.get(), EVP_sha256(), plaintext,
                           absl::MakeSpan(ciphertext)));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session_, &mech, private_key_));

  CK_ULONG plaintext_size;
  EXPECT_OK(Decrypt(session_, ciphertext, sizeof(ciphertext), nullptr,
                    &plaintext_size));
  EXPECT_EQ(plaintext_size, plaintext.size());

  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(Decrypt(session_, ciphertext, sizeof(ciphertext),
                    recovered_plaintext.data(), &plaintext_size));
  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session_, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricCryptTest, DecryptSuccessSameBuffer) {
  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> buf(256);
  EXPECT_OK(EncryptRsaOaep(pub_pkey_.get(), EVP_sha256(), plaintext,
                           absl::MakeSpan(buf)));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session_, &mech, private_key_));

  CK_ULONG plaintext_size = buf.size();
  EXPECT_OK(
      Decrypt(session_, buf.data(), buf.size(), buf.data(), &plaintext_size));
  EXPECT_EQ(plaintext_size, plaintext.size());

  buf.resize(plaintext_size);
  EXPECT_EQ(buf, plaintext);
}

TEST_F(AsymmetricCryptTest, DecryptBufferTooSmall) {
  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  uint8_t ciphertext[256];
  EXPECT_OK(EncryptRsaOaep(pub_pkey_.get(), EVP_sha256(), plaintext,
                           absl::MakeSpan(ciphertext)));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session_, &mech, private_key_));

  std::vector<uint8_t> recovered_plaintext(32);
  CK_ULONG plaintext_size = recovered_plaintext.size();
  EXPECT_THAT(Decrypt(session_, ciphertext, sizeof(ciphertext),
                      recovered_plaintext.data(), &plaintext_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be able to proceed after CKR_BUFFER_TOO_SMALL.
  recovered_plaintext.resize(plaintext_size);
  EXPECT_OK(Decrypt(session_, ciphertext, sizeof(ciphertext),
                    recovered_plaintext.data(), &plaintext_size));
  EXPECT_EQ(plaintext, recovered_plaintext);

  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session_, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricCryptTest, DecryptParametersMismatch) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA512, CKG_MGF1_SHA512,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(DecryptInit(session_, &mech, private_key_),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST_F(AsymmetricCryptTest, DecryptInitFailsInvalidSessionHandle) {
  EXPECT_THAT(DecryptInit(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(AsymmetricCryptTest, DecryptInitFailsInvalidKeyHandle) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(DecryptInit(session_, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_F(AsymmetricCryptTest, DecryptInitFailsOperationActive) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session_, &mech, private_key_));
  EXPECT_THAT(DecryptInit(session_, &mech, private_key_),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(AsymmetricCryptTest, DecryptFailsOperationNotInitialized) {
  uint8_t ciphertext[256];
  CK_ULONG plaintext_size;
  EXPECT_THAT(Decrypt(session_, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricCryptTest, DecryptFailsNullCiphertext) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session_, &mech, private_key_));

  CK_ULONG plaintext_size;
  EXPECT_THAT(Decrypt(session_, nullptr, 0, nullptr, &plaintext_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST_F(AsymmetricCryptTest, DecryptFailsNullPlaintextSize) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session_, &mech, private_key_));

  uint8_t ciphertext[256];
  EXPECT_THAT(
      Decrypt(session_, ciphertext, sizeof(ciphertext), nullptr, nullptr),
      StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST_F(AsymmetricCryptTest, EncryptSuccess) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session_, &mech, public_key_));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  CK_ULONG ciphertext_size;
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                    &ciphertext_size));
  EXPECT_EQ(ciphertext_size, 256);

  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));

  // Operation should be terminated after success
  EXPECT_THAT(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricCryptTest, EncryptSuccessSameBuffer) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session_, &mech, public_key_));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> buf(256);
  std::copy(plaintext.begin(), plaintext.end(), buf.data());

  CK_ULONG ciphertext_size = buf.size();
  EXPECT_OK(Encrypt(session_, buf.data(), 128, buf.data(), &ciphertext_size));
  EXPECT_EQ(ciphertext_size, 256);

  EXPECT_OK(DecryptInit(session_, &mech, private_key_));

  std::vector<uint8_t> recovered_plaintext(128);
  CK_ULONG recovered_plaintext_size = recovered_plaintext.size();
  EXPECT_OK(Decrypt(session_, buf.data(), buf.size(),
                    recovered_plaintext.data(), &recovered_plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);
}

TEST_F(AsymmetricCryptTest, EncryptBufferTooSmall) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session_, &mech, public_key_));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> ciphertext(255);
  CK_ULONG ciphertext_size = ciphertext.size();
  EXPECT_THAT(Encrypt(session_, plaintext.data(), plaintext.size(),
                      ciphertext.data(), &ciphertext_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(ciphertext_size, 256);

  // Operation should be able to proceed after CKR_BUFFER_TOO_SMALL.
  ciphertext.resize(ciphertext_size);
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));

  // Operation should now be terminated.
  EXPECT_THAT(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricCryptTest, EncryptParametersMismatch) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA512, CKG_MGF1_SHA512,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(EncryptInit(session_, &mech, public_key_),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST_F(AsymmetricCryptTest, EncryptInitFailsInvalidSessionHandle) {
  EXPECT_THAT(EncryptInit(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(AsymmetricCryptTest, EncryptInitFailsInvalidKeyHandle) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(EncryptInit(session_, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_F(AsymmetricCryptTest, EncryptInitFailsOperationActive) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session_, &mech, public_key_));
  EXPECT_THAT(EncryptInit(session_, &mech, public_key_),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(AsymmetricCryptTest, EncryptFailsOperationNotInitialized) {
  uint8_t plaintext[32];
  CK_ULONG ciphertext_size;
  EXPECT_THAT(Encrypt(session_, plaintext, sizeof(plaintext), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricCryptTest, EncryptFailsNullPLaintext) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session_, &mech, public_key_));

  CK_ULONG ciphertext_size;
  EXPECT_THAT(Encrypt(session_, nullptr, 0, nullptr, &ciphertext_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST_F(AsymmetricCryptTest, EncryptFailsNullCiphertextSize) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session_, &mech, public_key_));

  uint8_t plaintext[32];
  EXPECT_THAT(Encrypt(session_, plaintext, sizeof(plaintext), nullptr, nullptr),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

class AsymmetricSignTest : public BridgeTest {
 protected:
  void SetUp() override {
    BridgeTest::SetUp();
    auto kms_client = fake_kms_->NewClient();

    kms_v1::CryptoKey ck;
    ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
    ck.mutable_version_template()->set_algorithm(
        kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
    ck.mutable_version_template()->set_protection_level(
        kms_v1::ProtectionLevel::HSM);
    ck = CreateCryptoKeyOrDie(kms_client.get(), kr1_.name(), "ck", ck, true);

    kms_v1::CryptoKeyVersion ckv;
    ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
    ckv = WaitForEnablement(kms_client.get(), ckv);

    kms_v1::PublicKey pub_proto = GetPublicKey(kms_client.get(), ckv);
    ASSERT_OK_AND_ASSIGN(pub_pkey_, ParseX509PublicKeyPem(pub_proto.pem()));

    EXPECT_OK(Initialize(&init_args_));
    EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session_));

    CK_OBJECT_CLASS object_class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE attr_template[2] = {
        {CKA_ID, const_cast<char*>(ckv.name().data()), ckv.name().size()},
        {CKA_CLASS, &object_class, sizeof(object_class)},
    };
    CK_ULONG found_count;

    EXPECT_OK(FindObjectsInit(session_, attr_template, 2));
    EXPECT_OK(FindObjects(session_, &private_key_, 1, &found_count));
    EXPECT_EQ(found_count, 1);
    EXPECT_OK(FindObjectsFinal(session_));

    object_class = CKO_PUBLIC_KEY;
    EXPECT_OK(FindObjectsInit(session_, attr_template, 2));
    EXPECT_OK(FindObjects(session_, &public_key_, 1, &found_count));
    EXPECT_EQ(found_count, 1);
    EXPECT_OK(FindObjectsFinal(session_))
  }

  void TearDown() override { EXPECT_OK(Finalize(nullptr)); }

  CK_SESSION_HANDLE session_;
  CK_OBJECT_HANDLE private_key_;
  CK_OBJECT_HANDLE public_key_;
  bssl::UniquePtr<EVP_PKEY> pub_pkey_;
};

TEST_F(AsymmetricSignTest, SignVerifySuccess) {
  std::vector<uint8_t> data(128);
  RAND_bytes(data.data(), data.size());

  uint8_t hash[32];
  SHA256(data.data(), data.size(), hash);

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};

  EXPECT_OK(SignInit(session_, &mech, private_key_));

  CK_ULONG signature_size;
  EXPECT_OK(Sign(session_, hash, sizeof(hash), nullptr, &signature_size));
  EXPECT_EQ(signature_size, 64);

  std::vector<uint8_t> signature(signature_size);
  EXPECT_OK(
      Sign(session_, hash, sizeof(hash), signature.data(), &signature_size));

  EXPECT_OK(VerifyInit(session_, &mech, public_key_));
  EXPECT_OK(
      Verify(session_, hash, sizeof(hash), signature.data(), signature.size()));

  // Operation should be terminated after success
  EXPECT_THAT(
      Verify(session_, hash, sizeof(hash), signature.data(), signature.size()),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, SignHashTooSmall) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));

  uint8_t hash[31], sig[64];
  CK_ULONG signature_size = sizeof(sig);
  EXPECT_THAT(Sign(session_, hash, sizeof(hash), sig, &signature_size),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AsymmetricSignTest, SignSameBuffer) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));

  std::vector<uint8_t> digest(32);
  RAND_bytes(digest.data(), digest.size());

  std::vector<uint8_t> buf(64);
  std::copy(digest.begin(), digest.end(), buf.begin());
  CK_ULONG signature_size = buf.size();

  EXPECT_OK(Sign(session_, buf.data(), 32, buf.data(), &signature_size));

  EXPECT_OK(EcdsaVerifyP1363(EVP_PKEY_get0_EC_KEY(pub_pkey_.get()),
                             EVP_sha256(), digest, buf));
}

TEST_F(AsymmetricSignTest, SignBufferTooSmall) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));

  std::vector<uint8_t> hash(32), sig(63);
  CK_ULONG signature_size = sig.size();
  EXPECT_THAT(
      Sign(session_, hash.data(), hash.size(), sig.data(), &signature_size),
      StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(signature_size, 64);

  sig.resize(signature_size);
  EXPECT_OK(
      Sign(session_, hash.data(), hash.size(), sig.data(), &signature_size));

  // Operation should now be terminated.
  EXPECT_THAT(
      Sign(session_, hash.data(), hash.size(), sig.data(), &signature_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, SignInitFailsInvalidSessionHandle) {
  EXPECT_THAT(SignInit(0, nullptr, 0), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(AsymmetricSignTest, SignInitFailsInvalidKeyHandle) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_THAT(SignInit(session_, &mech, 0), StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_F(AsymmetricSignTest, SignInitFailsOperationActive) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));
  EXPECT_THAT(SignInit(session_, &mech, private_key_),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(AsymmetricSignTest, SignFailsOperationNotInitialized) {
  uint8_t hash[32];
  CK_ULONG signature_size;
  EXPECT_THAT(Sign(session_, hash, sizeof(hash), nullptr, &signature_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, SignFailsNullHash) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));

  CK_ULONG signature_size;
  EXPECT_THAT(Sign(session_, nullptr, 0, nullptr, &signature_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST_F(AsymmetricSignTest, VerifyFailsNullSignatureSize) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));

  uint8_t hash[32];
  EXPECT_THAT(Sign(session_, hash, sizeof(hash), nullptr, nullptr),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST_F(AsymmetricSignTest, VerifyInvalidSignature) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));

  uint8_t hash[32], sig[64];
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_SIGNATURE_INVALID));

  // Operation should be terminated after failure
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, VerifyHashTooSmall) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));

  uint8_t hash[31], sig[64];
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_DATA_LEN_RANGE));

  // Operation should be terminated after failure
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, VerifyHashTooLarge) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));

  uint8_t hash[33], sig[64];
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AsymmetricSignTest, VerifySignatureTooSmall) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));

  uint8_t hash[32], sig[63];
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_SIGNATURE_LEN_RANGE));

  // Operation should be terminated after failure
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, VerifySignatureTooLarge) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));

  uint8_t hash[32], sig[65];
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_SIGNATURE_LEN_RANGE));
}

TEST_F(AsymmetricSignTest, VerifyInitFailsInvalidSessionHandle) {
  EXPECT_THAT(VerifyInit(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(AsymmetricSignTest, VerifyInitFailsInvalidKeyHandle) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_THAT(VerifyInit(session_, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_F(AsymmetricSignTest, VerifyInitFailsOperationActive) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));
  EXPECT_THAT(VerifyInit(session_, &mech, public_key_),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(AsymmetricSignTest, VerifyFailsOperationNotInitialized) {
  uint8_t hash[32], sig[64];
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, VerifyFailsNullHash) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));

  uint8_t sig[64];
  EXPECT_THAT(Verify(session_, nullptr, 0, sig, sizeof(sig)),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST_F(AsymmetricSignTest, VerifyFailsNullSignature) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));

  uint8_t hash[32];
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), nullptr, 0),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

}  // namespace
}  // namespace kmsp11