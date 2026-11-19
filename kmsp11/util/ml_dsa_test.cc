// Copyright 2026 Google LLC
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

#include "kmsp11/util/ml_dsa.h"

#include "common/openssl.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "kmsp11/test/matchers.h"

#if defined(OPENSSL_IS_BORINGSSL) && defined(__has_include)
#if __has_include("openssl/mldsa.h")
#include "openssl/mldsa.h"
#define KMSP11_HAVE_MLDSA 1
#endif
#endif

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::ElementsAreArray;
using ::testing::StartsWith;

class MlDsaParamTest
    : public testing::TestWithParam<CK_ML_DSA_PARAMETER_SET_TYPE> {};

INSTANTIATE_TEST_SUITE_P(AllParameterSets, MlDsaParamTest,
                         testing::Values(CKP_ML_DSA_44, CKP_ML_DSA_65,
                                         CKP_ML_DSA_87));

TEST_P(MlDsaParamTest, MarshalParseRoundTrip) {
  ASSERT_OK_AND_ASSIGN(MlDsaSizes sizes, GetMlDsaSizes(GetParam()));
  std::string pub(sizes.public_key_bytes, '\x5a');

  ASSERT_OK_AND_ASSIGN(std::string der,
                       MarshalMlDsaPublicKeyDer(GetParam(), pub));
  ASSERT_OK_AND_ASSIGN(MlDsaPublicKey parsed, ParseMlDsaPublicKeyDer(der));
  EXPECT_EQ(parsed.parameter_set, GetParam());
  EXPECT_EQ(parsed.value, pub);
}

TEST(MlDsaTest, MarshalMlDsa65MatchesRfc9881Encoding) {
  std::string pub(1952, '\0');
  ASSERT_OK_AND_ASSIGN(std::string der,
                       MarshalMlDsaPublicKeyDer(CKP_ML_DSA_65, pub));

  // SEQUENCE(1970) { SEQUENCE(11) { OID 2.16.840.1.101.3.4.3.18 },
  //                  BIT STRING(1953) { 0x00 unused bits, key } }
  const uint8_t kExpectedPrefix[] = {
      0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x03, 0x12, 0x03, 0x82, 0x07, 0xa1, 0x00};
  EXPECT_EQ(der.size(), sizeof(kExpectedPrefix) + pub.size());
  EXPECT_THAT(der, StartsWith(std::string(
                       reinterpret_cast<const char*>(kExpectedPrefix),
                       sizeof(kExpectedPrefix))));
}

TEST(MlDsaTest, MarshalRejectsWrongLength) {
  EXPECT_FALSE(
      MarshalMlDsaPublicKeyDer(CKP_ML_DSA_65, std::string(1312, 'a')).ok());
}

TEST(MlDsaTest, ParseRejectsTrailingData) {
  ASSERT_OK_AND_ASSIGN(
      std::string der,
      MarshalMlDsaPublicKeyDer(CKP_ML_DSA_44, std::string(1312, 'a')));
  der.push_back('\0');
  EXPECT_FALSE(ParseMlDsaPublicKeyDer(der).ok());
}

TEST(MlDsaTest, ParseRejectsWrongOid) {
  ASSERT_OK_AND_ASSIGN(
      std::string der,
      MarshalMlDsaPublicKeyDer(CKP_ML_DSA_44, std::string(1312, 'a')));
  der[16] = 0x14;  // id-slh-dsa-sha2-128s
  EXPECT_FALSE(ParseMlDsaPublicKeyDer(der).ok());
}

TEST(MlDsaTest, ParseRejectsMismatchedKeyLength) {
  // An ML-DSA-65 OID wrapping an ML-DSA-44 length key.
  ASSERT_OK_AND_ASSIGN(
      std::string der,
      MarshalMlDsaPublicKeyDer(CKP_ML_DSA_44, std::string(1312, 'a')));
  der[16] = 0x12;
  EXPECT_FALSE(ParseMlDsaPublicKeyDer(der).ok());
}

TEST(MlDsaTest, ParseRejectsTruncated) {
  ASSERT_OK_AND_ASSIGN(
      std::string der,
      MarshalMlDsaPublicKeyDer(CKP_ML_DSA_44, std::string(1312, 'a')));
  EXPECT_FALSE(ParseMlDsaPublicKeyDer(der.substr(0, der.size() - 1)).ok());
  EXPECT_FALSE(ParseMlDsaPublicKeyDer("").ok());
}

TEST(MlDsaTest, ParameterSetForAlgorithm) {
  EXPECT_THAT(
      MlDsaParameterSetForAlgorithm(kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_44),
      IsOkAndHolds(CKP_ML_DSA_44));
  EXPECT_THAT(
      MlDsaParameterSetForAlgorithm(kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_65),
      IsOkAndHolds(CKP_ML_DSA_65));
  EXPECT_THAT(
      MlDsaParameterSetForAlgorithm(kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_87),
      IsOkAndHolds(CKP_ML_DSA_87));
  EXPECT_FALSE(IsMlDsaAlgorithm(
      kms_v1::CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256));
  EXPECT_FALSE(IsMlDsaAlgorithm(
      kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_65_EXTERNAL_MU));
}

#ifdef KMSP11_HAVE_MLDSA

TEST(MlDsaTest, VerifySupported) { EXPECT_TRUE(MlDsaVerificationSupported()); }

class MlDsa65VerifyTest : public testing::Test {
 protected:
  void SetUp() override {
    priv_ = std::make_unique<MLDSA65_private_key>();
    uint8_t pub[MLDSA65_PUBLIC_KEY_BYTES];
    uint8_t seed[MLDSA_SEED_BYTES];
    ASSERT_EQ(MLDSA65_generate_key(pub, seed, priv_.get()), 1);
    pub_ = MlDsaPublicKey{CKP_ML_DSA_65,
                          std::string(reinterpret_cast<char*>(pub),
                                      sizeof(pub))};
  }

  std::vector<uint8_t> Sign(std::string_view msg, std::string_view ctx) {
    std::vector<uint8_t> sig(MLDSA65_SIGNATURE_BYTES);
    EXPECT_EQ(MLDSA65_sign(sig.data(), priv_.get(),
                           reinterpret_cast<const uint8_t*>(msg.data()),
                           msg.size(),
                           reinterpret_cast<const uint8_t*>(ctx.data()),
                           ctx.size()),
              1);
    return sig;
  }

  static absl::Span<const uint8_t> Bytes(std::string_view s) {
    return absl::MakeConstSpan(reinterpret_cast<const uint8_t*>(s.data()),
                               s.size());
  }

  std::unique_ptr<MLDSA65_private_key> priv_;
  MlDsaPublicKey pub_;
};

TEST_F(MlDsa65VerifyTest, VerifySuccess) {
  std::vector<uint8_t> sig = Sign("hello", "");
  EXPECT_OK(MlDsaVerify(pub_, Bytes("hello"), {}, sig));
}

TEST_F(MlDsa65VerifyTest, VerifySuccessWithContext) {
  std::vector<uint8_t> sig = Sign("hello", "ctx");
  EXPECT_OK(MlDsaVerify(pub_, Bytes("hello"), Bytes("ctx"), sig));
  EXPECT_THAT(MlDsaVerify(pub_, Bytes("hello"), {}, sig),
              StatusRvIs(CKR_SIGNATURE_INVALID));
}

TEST_F(MlDsa65VerifyTest, VerifyWrongMessage) {
  std::vector<uint8_t> sig = Sign("hello", "");
  EXPECT_THAT(MlDsaVerify(pub_, Bytes("goodbye"), {}, sig),
              StatusRvIs(CKR_SIGNATURE_INVALID));
}

TEST_F(MlDsa65VerifyTest, VerifyWrongSignatureLength) {
  std::vector<uint8_t> sig = Sign("hello", "");
  sig.pop_back();
  EXPECT_THAT(MlDsaVerify(pub_, Bytes("hello"), {}, sig),
              StatusRvIs(CKR_SIGNATURE_LEN_RANGE));
}

#else

TEST(MlDsaTest, VerifyUnsupported) {
  EXPECT_FALSE(MlDsaVerificationSupported());
  MlDsaPublicKey pub{CKP_ML_DSA_65, std::string(1952, 'a')};
  std::vector<uint8_t> sig(3309);
  EXPECT_THAT(MlDsaVerify(pub, {}, {}, sig), StatusRvIs(CKR_MECHANISM_INVALID));
}

#endif  // KMSP11_HAVE_MLDSA

}  // namespace
}  // namespace cloud_kms::kmsp11
