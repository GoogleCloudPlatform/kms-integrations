#include "kmsp11/token.h"

#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/string_utils.h"

namespace kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Field;
using ::testing::Le;

class TokenTest : public testing::Test {
 protected:
  inline void SetUp() override {
    ASSERT_OK_AND_ASSIGN(token_, Token::New(0, TokenConfig()));
    slot_info_ = token_->slot_info();
    token_info_ = token_->token_info();
  }

  std::unique_ptr<Token> token_;
  CK_SLOT_INFO slot_info_;
  CK_TOKEN_INFO token_info_;
};

TEST_F(TokenTest, SlotInfoSlotDescriptionIsSet) {
  EXPECT_EQ(StrFromBytes(slot_info_.slotDescription),
            // Note the space-padding to get to 64 characters
            "A virtual slot mapped to a key ring in Google Cloud KMS         ");
}

TEST_F(TokenTest, SlotInfoManufacturerIdIsSet) {
  EXPECT_EQ(StrFromBytes(slot_info_.manufacturerID),
            // Note the space-padding to get to 32 characters
            "Google                          ");
}

TEST_F(TokenTest, SlotInfoFlagsAreSet) {
  EXPECT_EQ(slot_info_.flags, CKF_TOKEN_PRESENT);
}

TEST_F(TokenTest, SlotInfoHardwareVersionIsZero) {
  EXPECT_THAT(slot_info_.hardwareVersion,
              AllOf(Field("major", &CK_VERSION::major, 0),
                    Field("minor", &CK_VERSION::minor, 0)));
}

TEST_F(TokenTest, SlotInfoFirmwareVersionIsZero) {
  EXPECT_THAT(slot_info_.firmwareVersion,
              AllOf(Field("major", &CK_VERSION::major, 0),
                    Field("minor", &CK_VERSION::minor, 0)));
}

TEST_F(TokenTest, TokenInfoLabelDefaultUnset) {
  EXPECT_EQ(StrFromBytes(token_info_.label), std::string(32, ' '));
}

TEST_F(TokenTest, TokenInfoLabelExplicitValue) {
  TokenConfig config;
  config.set_label("foo bar");

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token, Token::New(0, config));
  EXPECT_EQ(StrFromBytes(token->token_info().label),
            // Note the space-padding to get to 32 characters
            "foo bar                         ");
}

TEST_F(TokenTest, TokenInfoManufacturerIdIsSet) {
  EXPECT_EQ(StrFromBytes(token_info_.manufacturerID),
            // Note the space-padding to get to 32 characters
            "Google                          ");
}

TEST_F(TokenTest, TokenInfoModelIsSet) {
  EXPECT_EQ(StrFromBytes(token_info_.model),
            // Note the space-padding to get to 16 characters
            "Cloud KMS Token ");
}

TEST_F(TokenTest, SerialNumberIsSet) {
  EXPECT_EQ(StrFromBytes(token_info_.serialNumber), "0000000000000000");
}

TEST_F(TokenTest, FlagValues) {
  EXPECT_EQ(token_info_.flags & CKF_WRITE_PROTECTED, CKF_WRITE_PROTECTED);
  EXPECT_EQ(token_info_.flags & CKF_USER_PIN_INITIALIZED,
            CKF_USER_PIN_INITIALIZED);
  EXPECT_EQ(token_info_.flags & CKF_TOKEN_INITIALIZED, CKF_TOKEN_INITIALIZED);
  EXPECT_EQ(token_info_.flags & CKF_SO_PIN_LOCKED, CKF_SO_PIN_LOCKED);
}

TEST_F(TokenTest, MaxSessionCountIsEffectivelyInfinite) {
  EXPECT_EQ(token_info_.ulMaxSessionCount, CK_EFFECTIVELY_INFINITE);
}

TEST_F(TokenTest, MaxRwSessionCountIsZero) {
  EXPECT_EQ(token_info_.ulMaxRwSessionCount, 0);
}

TEST_F(TokenTest, SessionCountsUnavailable) {
  EXPECT_EQ(token_info_.ulSessionCount, CK_UNAVAILABLE_INFORMATION);
  EXPECT_EQ(token_info_.ulRwSessionCount, CK_UNAVAILABLE_INFORMATION);
}

TEST_F(TokenTest, PinLengthMinAndMaxIsZero) {
  EXPECT_EQ(token_info_.ulMaxPinLen, 0);
  EXPECT_EQ(token_info_.ulMinPinLen, 0);
}

TEST_F(TokenTest, MemoryStatsUnavailable) {
  EXPECT_EQ(token_info_.ulTotalPublicMemory, CK_UNAVAILABLE_INFORMATION);
  EXPECT_EQ(token_info_.ulFreePublicMemory, CK_UNAVAILABLE_INFORMATION);
  EXPECT_EQ(token_info_.ulTotalPrivateMemory, CK_UNAVAILABLE_INFORMATION);
  EXPECT_EQ(token_info_.ulFreePrivateMemory, CK_UNAVAILABLE_INFORMATION);
}

TEST_F(TokenTest, TokenInfoHardwareVersionIsZero) {
  EXPECT_THAT(token_info_.hardwareVersion,
              AllOf(Field("major", &CK_VERSION::major, 0),
                    Field("minor", &CK_VERSION::minor, 0)));
}

TEST_F(TokenTest, TokenInfoFirmwareVersionIsZero) {
  EXPECT_THAT(token_info_.firmwareVersion,
              AllOf(Field("major", &CK_VERSION::major, 0),
                    Field("minor", &CK_VERSION::minor, 0)));
}

TEST_F(TokenTest, UtcTimeIsSet) {
  EXPECT_EQ(StrFromBytes(token_info_.utcTime), "0000000000000000");
}

TEST_F(TokenTest, InfoContainsSlotId) {
  EXPECT_EQ(token_->session_info().slotID, 0);
}

TEST_F(TokenTest, DefaultStateRoPublicSession) {
  EXPECT_EQ(token_->session_info().state, CKS_RO_PUBLIC_SESSION);
}

TEST_F(TokenTest, SessionFlagsSerial) {
  EXPECT_EQ(token_->session_info().flags & CKF_SERIAL_SESSION,
            CKF_SERIAL_SESSION);
}

TEST_F(TokenTest, SessionErrorIsZero) {
  EXPECT_EQ(token_->session_info().ulDeviceError, 0);
}

TEST_F(TokenTest, LoginAsUserSuccess) {
  EXPECT_OK(token_->Login(CKU_USER));
  EXPECT_EQ(token_->session_info().state, CKS_RO_USER_FUNCTIONS);
}

TEST_F(TokenTest, LoginAsUserFailsOnRelogin) {
  EXPECT_OK(token_->Login(CKU_USER));
  EXPECT_THAT(token_->Login(CKU_USER), StatusRvIs(CKR_USER_ALREADY_LOGGED_IN));
}

TEST_F(TokenTest, LoginAsSOFails) {
  EXPECT_THAT(token_->Login(CKU_SO), StatusRvIs(CKR_PIN_LOCKED));
}

TEST_F(TokenTest, LoginAsContextSpecificFails) {
  EXPECT_THAT(token_->Login(CKU_CONTEXT_SPECIFIC),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(TokenTest, LoginLogoutSucceeds) {
  EXPECT_OK(token_->Login(CKU_USER));
  EXPECT_OK(token_->Logout());
  EXPECT_EQ(token_->session_info().state, CKS_RO_PUBLIC_SESSION);
}

TEST_F(TokenTest, LogoutWithoutLoginFails) {
  EXPECT_THAT(token_->Logout(), StatusRvIs(CKR_USER_NOT_LOGGED_IN));
}

}  // namespace
}  // namespace kmsp11
