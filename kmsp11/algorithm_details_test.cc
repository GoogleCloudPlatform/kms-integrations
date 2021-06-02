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

#include "kmsp11/algorithm_details.h"

#include "kmsp11/test/test_status_macros.h"

namespace kmsp11 {
namespace {

using ::testing::ElementsAre;

TEST(GetAlgorithmDetailsTest, AlgorithmEc) {
  ASSERT_OK_AND_ASSIGN(
      AlgorithmDetails details,
      GetDetails(kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384));

  EXPECT_EQ(details.algorithm, kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384);
  EXPECT_EQ(details.purpose, kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  EXPECT_THAT(details.allowed_mechanisms, ElementsAre(CKM_ECDSA));
  EXPECT_EQ(details.key_type, CKK_EC);
  EXPECT_EQ(details.key_bit_length, 384);
  EXPECT_EQ(details.key_gen_mechanism, CKM_EC_KEY_PAIR_GEN);
  EXPECT_EQ(details.digest_mechanism, CKM_SHA384);
}

TEST(GetAlgorithmDetailsTest, AlgorithmRsaOaep) {
  ASSERT_OK_AND_ASSIGN(
      AlgorithmDetails details,
      GetDetails(kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_4096_SHA256));

  EXPECT_EQ(details.algorithm,
            kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_4096_SHA256);
  EXPECT_EQ(details.purpose, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
  EXPECT_THAT(details.allowed_mechanisms, ElementsAre(CKM_RSA_PKCS_OAEP));
  EXPECT_EQ(details.key_type, CKK_RSA);
  EXPECT_EQ(details.key_bit_length, 4096);
  EXPECT_EQ(details.key_gen_mechanism, CKM_RSA_PKCS_KEY_PAIR_GEN);
  EXPECT_EQ(details.digest_mechanism, CKM_SHA256);
}

TEST(GetAlgorithmDetailsTest, AlgorithmNotFound) {
  absl::StatusOr<AlgorithmDetails> details =
      GetDetails(kms_v1::CryptoKeyVersion::EXTERNAL_SYMMETRIC_ENCRYPTION);
  EXPECT_FALSE(details.ok());
  EXPECT_THAT(details.status(), StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(details.status(), StatusRvIs(CKR_GENERAL_ERROR));
}

}  // namespace
}  // namespace kmsp11