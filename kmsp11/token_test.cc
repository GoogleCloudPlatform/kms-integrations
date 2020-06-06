#include "kmsp11/token.h"

#include "gmock/gmock.h"
#include "kmsp11/test/fakekms/cpp/fakekms.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/kms_client.h"
#include "kmsp11/util/string_utils.h"

namespace kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Field;
using ::testing::IsEmpty;
using ::testing::Le;
using ::testing::Pointee;
using ::testing::Property;

class TokenTest : public testing::Test {
 protected:
  inline void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_kms_, FakeKms::New());

    auto fake_client = fake_kms_->NewClient();
    key_ring_ = CreateKeyRingOrDie(fake_client.get(), kTestLocation, RandomId(),
                                   key_ring_);

    config_.set_key_ring(key_ring_.name());
    client_ = absl::make_unique<KmsClient>(fake_kms_->listen_addr(),
                                           grpc::InsecureChannelCredentials(),
                                           absl::Seconds(1));
  }

  std::unique_ptr<FakeKms> fake_kms_;
  kms_v1::KeyRing key_ring_;
  TokenConfig config_;
  std::unique_ptr<KmsClient> client_;
};

TEST_F(TokenTest, SlotInfoSlotDescriptionIsSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(StrFromBytes(token->slot_info().slotDescription),
            // Note the space-padding to get to 64 characters
            "A virtual slot mapped to a key ring in Google Cloud KMS         ");
}

TEST_F(TokenTest, SlotInfoManufacturerIdIsSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  EXPECT_EQ(StrFromBytes(token->slot_info().manufacturerID),
            // Note the space-padding to get to 32 characters
            "Google                          ");
}

TEST_F(TokenTest, SlotInfoFlagsAreSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(token->slot_info().flags, CKF_TOKEN_PRESENT);
}

TEST_F(TokenTest, SlotInfoHardwareVersionIsZero) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->slot_info().hardwareVersion,
              AllOf(Field("major", &CK_VERSION::major, 0),
                    Field("minor", &CK_VERSION::minor, 0)));
}

TEST_F(TokenTest, SlotInfoFirmwareVersionIsZero) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->slot_info().firmwareVersion,
              AllOf(Field("major", &CK_VERSION::major, 0),
                    Field("minor", &CK_VERSION::minor, 0)));
}

TEST_F(TokenTest, TokenInfoLabelDefaultUnset) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(StrFromBytes(token->token_info().label), std::string(32, ' '));
}

TEST_F(TokenTest, TokenInfoLabelExplicitValue) {
  config_.set_label("foo bar");
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(StrFromBytes(token->token_info().label),
            // Note the space-padding to get to 32 characters
            "foo bar                         ");
}

TEST_F(TokenTest, TokenInfoManufacturerIdIsSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(StrFromBytes(token->token_info().manufacturerID),
            // Note the space-padding to get to 32 characters
            "Google                          ");
}

TEST_F(TokenTest, TokenInfoModelIsSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(StrFromBytes(token->token_info().model),
            // Note the space-padding to get to 16 characters
            "Cloud KMS Token ");
}

TEST_F(TokenTest, SerialNumberIsSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(StrFromBytes(token->token_info().serialNumber), "0000000000000000");
}

TEST_F(TokenTest, FlagValues) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();

  EXPECT_EQ(info.flags & CKF_WRITE_PROTECTED, CKF_WRITE_PROTECTED);
  EXPECT_EQ(info.flags & CKF_USER_PIN_INITIALIZED, CKF_USER_PIN_INITIALIZED);
  EXPECT_EQ(info.flags & CKF_TOKEN_INITIALIZED, CKF_TOKEN_INITIALIZED);
  EXPECT_EQ(info.flags & CKF_SO_PIN_LOCKED, CKF_SO_PIN_LOCKED);
}

TEST_F(TokenTest, MaxSessionCountIsEffectivelyInfinite) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();

  EXPECT_EQ(info.ulMaxSessionCount, CK_EFFECTIVELY_INFINITE);
}

TEST_F(TokenTest, MaxRwSessionCountIsZero) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();

  EXPECT_EQ(info.ulMaxRwSessionCount, 0);
}

TEST_F(TokenTest, SessionCountsUnavailable) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();

  EXPECT_EQ(info.ulSessionCount, CK_UNAVAILABLE_INFORMATION);
  EXPECT_EQ(info.ulRwSessionCount, CK_UNAVAILABLE_INFORMATION);
}

TEST_F(TokenTest, PinLengthMinAndMaxIsZero) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();

  EXPECT_EQ(info.ulMaxPinLen, 0);
  EXPECT_EQ(info.ulMinPinLen, 0);
}

TEST_F(TokenTest, MemoryStatsUnavailable) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();

  EXPECT_EQ(info.ulTotalPublicMemory, CK_UNAVAILABLE_INFORMATION);
  EXPECT_EQ(info.ulFreePublicMemory, CK_UNAVAILABLE_INFORMATION);
  EXPECT_EQ(info.ulTotalPrivateMemory, CK_UNAVAILABLE_INFORMATION);
  EXPECT_EQ(info.ulFreePrivateMemory, CK_UNAVAILABLE_INFORMATION);
}

TEST_F(TokenTest, TokenInfoHardwareVersionIsZero) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();

  EXPECT_THAT(info.hardwareVersion,
              AllOf(Field("major", &CK_VERSION::major, 0),
                    Field("minor", &CK_VERSION::minor, 0)));
}

TEST_F(TokenTest, TokenInfoFirmwareVersionIsZero) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();
  EXPECT_THAT(info.firmwareVersion,
              AllOf(Field("major", &CK_VERSION::major, 0),
                    Field("minor", &CK_VERSION::minor, 0)));
}

TEST_F(TokenTest, UtcTimeIsSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();

  EXPECT_EQ(StrFromBytes(info.utcTime), "0000000000000000");
}

TEST_F(TokenTest, InfoContainsSlotId) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  EXPECT_EQ(token->session_info().slotID, 0);
}

TEST_F(TokenTest, DefaultStateRoPublicSession) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(token->session_info().state, CKS_RO_PUBLIC_SESSION);
}

TEST_F(TokenTest, SessionFlagsSerial) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(token->session_info().flags & CKF_SERIAL_SESSION,
            CKF_SERIAL_SESSION);
}

TEST_F(TokenTest, SessionErrorIsZero) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(token->session_info().ulDeviceError, 0);
}

TEST_F(TokenTest, LoginAsUserSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_OK(token->Login(CKU_USER));
  EXPECT_EQ(token->session_info().state, CKS_RO_USER_FUNCTIONS);
}

TEST_F(TokenTest, LoginAsUserFailsOnRelogin) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_OK(token->Login(CKU_USER));
  EXPECT_THAT(token->Login(CKU_USER), StatusRvIs(CKR_USER_ALREADY_LOGGED_IN));
}

TEST_F(TokenTest, LoginAsSOFails) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->Login(CKU_SO), StatusRvIs(CKR_PIN_LOCKED));
}

TEST_F(TokenTest, LoginAsContextSpecificFails) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->Login(CKU_CONTEXT_SPECIFIC),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(TokenTest, LoginLogoutSucceeds) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_OK(token->Login(CKU_USER));
  EXPECT_OK(token->Logout());
  EXPECT_EQ(token->session_info().state, CKS_RO_PUBLIC_SESSION);
}

TEST_F(TokenTest, LogoutWithoutLoginFails) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->Logout(), StatusRvIs(CKR_USER_NOT_LOGGED_IN));
}

TEST_F(TokenTest, FindObjectsPublicBeforePrivate) {
  auto kms_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey_CryptoKeyPurpose_ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion_CryptoKeyVersionAlgorithm_EC_SIGN_P384_SHA384);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  std::vector<CK_ULONG> handles =
      token->FindObjects([](const Object& o) -> bool { return true; });
  EXPECT_EQ(handles.size(), 2);

  EXPECT_THAT(
      token->GetObject(handles[0]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv.name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));
  EXPECT_THAT(
      token->GetObject(handles[1]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv.name()),
          Property("object_class", &Object::object_class, CKO_PRIVATE_KEY)))));
}

TEST_F(TokenTest, FindObjectsKeyNamesSorted) {
  auto kms_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey_CryptoKeyPurpose_ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion_CryptoKeyVersionAlgorithm_EC_SIGN_P384_SHA384);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv1;
  ckv1 = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv1);
  ckv1 = WaitForEnablement(kms_client.get(), ckv1);

  kms_v1::CryptoKeyVersion ckv2;
  ckv2 = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv2);
  ckv2 = WaitForEnablement(kms_client.get(), ckv2);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  std::vector<CK_ULONG> handles =
      token->FindObjects([](const Object& o) -> bool {
        return o.object_class() == CKO_PUBLIC_KEY;
      });
  EXPECT_EQ(handles.size(), 2);

  EXPECT_THAT(
      token->GetObject(handles[0]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv1.name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));
  EXPECT_THAT(
      token->GetObject(handles[1]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv2.name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));
}

TEST_F(TokenTest, ObjectsEmptyHandleSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->FindObjects([](const Object& o) -> bool { return true; }),
              IsEmpty());
}

TEST_F(TokenTest, ObjectsUnknownHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->GetObject(1), StatusRvIs(CKR_OBJECT_HANDLE_INVALID));
}

TEST_F(TokenTest, EncryptDecryptKeyUnavailable) {
  auto kms_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey_CryptoKeyPurpose_ENCRYPT_DECRYPT);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "k", ck, false);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->FindObjects([](const Object& o) -> bool { return true; }),
              IsEmpty());
}

TEST_F(TokenTest, DisabledKeyUnavailable) {
  auto kms_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey_CryptoKeyPurpose_ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion_CryptoKeyVersionAlgorithm_EC_SIGN_P384_SHA384);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv1;
  ckv1 = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv1);
  ckv1 = WaitForEnablement(kms_client.get(), ckv1);

  kms_v1::CryptoKeyVersion ckv2;
  ckv2 = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv2);
  ckv2 = WaitForEnablement(kms_client.get(), ckv2);

  // Disable ckv1
  ckv1.set_state(kms_v1::CryptoKeyVersion_CryptoKeyVersionState_DISABLED);
  google::protobuf::FieldMask update_mask;
  update_mask.add_paths("state");
  ckv1 = UpdateCryptoKeyVersionOrDie(kms_client.get(), ckv1, update_mask);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  std::vector<CK_ULONG> handles =
      token->FindObjects([](const Object& o) -> bool { return true; });
  EXPECT_EQ(handles.size(), 2);

  EXPECT_THAT(
      token->GetObject(handles[0]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv2.name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));
  EXPECT_THAT(
      token->GetObject(handles[1]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv2.name()),
          Property("object_class", &Object::object_class, CKO_PRIVATE_KEY)))));
}

}  // namespace
}  // namespace kmsp11
