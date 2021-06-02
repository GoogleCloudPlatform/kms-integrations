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

#include "kmsp11/mechanism.h"

#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/test_status_macros.h"

namespace kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::Contains;

TEST(MechanismTest, SupportedMechanisms) {
  EXPECT_THAT(Mechanisms(),
              // Check a subset of the permitted mechanisms, to avoid having
              // this test be a change detector.
              AllOf(Contains(CKM_RSA_PKCS_KEY_PAIR_GEN),
                    Contains(CKM_RSA_PKCS_PSS), Contains(CKM_ECDSA)));
}

TEST(MechanismTest, DecryptFlag) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info,
                       MechanismInfo(CKM_RSA_PKCS_OAEP));
  EXPECT_EQ(info.flags & CKF_DECRYPT, CKF_DECRYPT);
}

TEST(MechanismTest, EncryptFlag) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info,
                       MechanismInfo(CKM_RSA_PKCS_OAEP));
  EXPECT_EQ(info.flags & CKF_ENCRYPT, CKF_ENCRYPT);
}

TEST(MechanismTest, SignFlag) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info, MechanismInfo(CKM_RSA_PKCS_PSS));
  EXPECT_EQ(info.flags & CKF_SIGN, CKF_SIGN);
}

TEST(MechanismTest, VerifyFlag) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info, MechanismInfo(CKM_RSA_PKCS));
  EXPECT_EQ(info.flags & CKF_VERIFY, CKF_VERIFY);
}

TEST(MechanismTest, RsaMin2048) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info,
                       MechanismInfo(CKM_RSA_PKCS_OAEP));
  EXPECT_EQ(info.ulMinKeySize, 2048);
}

TEST(MechanismTest, RsaMax4096) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info, MechanismInfo(CKM_RSA_PKCS));
  EXPECT_EQ(info.ulMaxKeySize, 4096);
}

TEST(MechanismTest, EcMax384) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info, MechanismInfo(CKM_ECDSA));
  EXPECT_EQ(info.ulMaxKeySize, 384);
}

TEST(MechanismTest, EcFlags) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info, MechanismInfo(CKM_ECDSA));
  EXPECT_EQ(info.flags & CKF_EC_F_P, CKF_EC_F_P);
  EXPECT_EQ(info.flags & CKF_EC_NAMEDCURVE, CKF_EC_NAMEDCURVE);
  EXPECT_EQ(info.flags & CKF_EC_UNCOMPRESS, CKF_EC_UNCOMPRESS);
}

TEST(MechanismTest, UnsupportedMechanism) {
  EXPECT_THAT(MechanismInfo(CKM_AES_GCM),
              testing::AllOf(StatusIs(absl::StatusCode::kNotFound),
                             StatusRvIs(CKR_MECHANISM_INVALID)));
}

}  // namespace
}  // namespace kmsp11
