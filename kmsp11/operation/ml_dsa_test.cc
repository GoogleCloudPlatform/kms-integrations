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

#include "kmsp11/operation/ml_dsa.h"

#include "common/kms_client.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "kmsp11/object.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/ml_dsa_fake_kms.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/util/ml_dsa.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {
namespace {


constexpr std::string_view kKeyRing =
    "projects/foo/locations/global/keyRings/bar";

absl::Span<const uint8_t> Bytes(std::string_view s) {
  return absl::MakeConstSpan(reinterpret_cast<const uint8_t*>(s.data()),
                             s.size());
}

class MlDsaTest : public testing::TestWithParam<
                      kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm> {
 protected:
  void SetUp() override {
    absl::StatusOr<std::unique_ptr<MlDsaFakeKms>> fake = MlDsaFakeKms::New();
    if (absl::IsUnimplemented(fake.status())) {
      GTEST_SKIP() << "crypto library does not support ML-DSA";
    }
    ASSERT_OK(fake);
    fake_ = std::move(*fake);

    client_ = std::make_unique<KmsClient>(KmsClient::Options{
        .endpoint_address = fake_->listen_addr(),
        .rpc_timeout = absl::Seconds(5),
    });

    ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKeyVersion ckv,
                         fake_->CreateKey(kKeyRing, "ck", GetParam()));

    kms_v1::GetPublicKeyRequest req;
    req.set_name(ckv.name());
    req.set_public_key_format(kms_v1::PublicKey::NIST_PQC);
    ASSERT_OK_AND_ASSIGN(kms_v1::PublicKey pub, client_->GetPublicKey(req));
    ASSERT_OK_AND_ASSIGN(CK_ML_DSA_PARAMETER_SET_TYPE ps,
                         MlDsaParameterSetForAlgorithm(GetParam()));
    ASSERT_OK_AND_ASSIGN(std::string der,
                         MarshalMlDsaPublicKeyDer(ps, pub.public_key().data()));
    ASSERT_OK_AND_ASSIGN(sizes_, GetMlDsaSizes(ps));

    ASSERT_OK_AND_ASSIGN(KeyPair kp, Object::NewKeyPair(ckv, der));
    pub_ = std::make_shared<Object>(kp.public_key);
    prv_ = std::make_shared<Object>(kp.private_key);
  }

  std::unique_ptr<MlDsaFakeKms> fake_;
  std::unique_ptr<KmsClient> client_;
  MlDsaSizes sizes_;
  std::shared_ptr<Object> pub_;
  std::shared_ptr<Object> prv_;
};

INSTANTIATE_TEST_SUITE_P(
    AllParameterSets, MlDsaTest,
    testing::Values(kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_44,
                    kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_65,
                    kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_87));

TEST_P(MlDsaTest, ObjectAttributes) {
  ASSERT_OK_AND_ASSIGN(CK_ML_DSA_PARAMETER_SET_TYPE ps,
                       MlDsaParameterSetForAlgorithm(GetParam()));
  for (const auto& obj : {pub_, prv_}) {
    EXPECT_EQ(obj->algorithm().key_type, CKK_ML_DSA);
    EXPECT_THAT(obj->attributes().Value(CKA_KEY_TYPE),
                IsOkAndHolds(MarshalULong(CKK_ML_DSA)));
    EXPECT_THAT(obj->attributes().Value(CKA_PARAMETER_SET),
                IsOkAndHolds(MarshalULong(ps)));
    EXPECT_THAT(obj->attributes().Value(CKA_KEY_GEN_MECHANISM),
                IsOkAndHolds(MarshalULong(CKM_ML_DSA_KEY_PAIR_GEN)));
  }

  ASSERT_OK_AND_ASSIGN(std::string_view value,
                       pub_->attributes().Value(CKA_VALUE));
  EXPECT_EQ(value.size(), sizes_.public_key_bytes);

  // Private key material is never exposed.
  EXPECT_THAT(prv_->attributes().Value(CKA_VALUE),
              StatusRvIs(CKR_ATTRIBUTE_SENSITIVE));
  EXPECT_THAT(prv_->attributes().Value(CKA_SEED),
              StatusRvIs(CKR_ATTRIBUTE_SENSITIVE));
  EXPECT_THAT(prv_->attributes().Value(CKA_SIGN),
              IsOkAndHolds(MarshalBool(true)));
  EXPECT_THAT(pub_->attributes().Value(CKA_VERIFY),
              IsOkAndHolds(MarshalBool(true)));
}

TEST_P(MlDsaTest, SignVerifySuccess) {
  CK_MECHANISM mech{CKM_ML_DSA, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(auto signer, NewMlDsaSigner(prv_, &mech));
  EXPECT_EQ(signer->signature_length(), sizes_.signature_bytes);

  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->Sign(client_.get(), Bytes("hello world"),
                         absl::MakeSpan(sig)));
  EXPECT_EQ(fake_->sign_count(), 1);

  ASSERT_OK_AND_ASSIGN(auto verifier, NewMlDsaVerifier(pub_, &mech));
  EXPECT_OK(verifier->Verify(client_.get(), Bytes("hello world"), sig));
  EXPECT_THAT(verifier->Verify(client_.get(), Bytes("hello there"), sig),
              StatusRvIs(CKR_SIGNATURE_INVALID));
}

TEST_P(MlDsaTest, SignHedgeRequiredParamSuccess) {
  CK_SIGN_ADDITIONAL_CONTEXT params{CKH_HEDGE_REQUIRED, nullptr, 0};
  CK_MECHANISM mech{CKM_ML_DSA, &params, sizeof(params)};
  ASSERT_OK_AND_ASSIGN(auto signer, NewMlDsaSigner(prv_, &mech));

  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->Sign(client_.get(), Bytes("msg"), absl::MakeSpan(sig)));

  CK_MECHANISM verify_mech{CKM_ML_DSA, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(auto verifier, NewMlDsaVerifier(pub_, &verify_mech));
  EXPECT_OK(verifier->Verify(client_.get(), Bytes("msg"), sig));
}

TEST_P(MlDsaTest, MultiPartSignVerify) {
  CK_MECHANISM mech{CKM_ML_DSA, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(auto signer, NewMlDsaSigner(prv_, &mech));
  EXPECT_OK(signer->SignUpdate(client_.get(), Bytes("hello ")));
  EXPECT_OK(signer->SignUpdate(client_.get(), Bytes("world")));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->SignFinal(client_.get(), absl::MakeSpan(sig)));

  ASSERT_OK_AND_ASSIGN(auto verifier, NewMlDsaVerifier(pub_, &mech));
  EXPECT_OK(verifier->VerifyUpdate(client_.get(), Bytes("hello")));
  EXPECT_OK(verifier->VerifyUpdate(client_.get(), Bytes(" world")));
  EXPECT_OK(verifier->VerifyFinal(client_.get(), sig));
}

TEST_P(MlDsaTest, SignFinalWithoutUpdateFails) {
  CK_MECHANISM mech{CKM_ML_DSA, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(auto signer, NewMlDsaSigner(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_THAT(signer->SignFinal(client_.get(), absl::MakeSpan(sig)),
              StatusRvIs(CKR_FUNCTION_FAILED));
}

TEST_P(MlDsaTest, SignMessageTooLong) {
  CK_MECHANISM mech{CKM_ML_DSA, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(auto signer, NewMlDsaSigner(prv_, &mech));
  std::string big(kMaxMlDsaMessageBytes + 1, 'a');
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_THAT(signer->Sign(client_.get(), Bytes(big), absl::MakeSpan(sig)),
              StatusRvIs(CKR_DATA_LEN_RANGE));
  EXPECT_EQ(fake_->sign_count(), 0);

  ASSERT_OK_AND_ASSIGN(auto signer2, NewMlDsaSigner(prv_, &mech));
  EXPECT_OK(signer2->SignUpdate(client_.get(),
                                Bytes(big.substr(0, kMaxMlDsaMessageBytes))));
  EXPECT_THAT(signer2->SignUpdate(client_.get(), Bytes("a")),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_P(MlDsaTest, VerifyDetectsCorruptSignatureFromKms) {
  fake_->set_corrupt_signatures(true);
  CK_MECHANISM mech{CKM_ML_DSA, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(auto signer, NewMlDsaSigner(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->Sign(client_.get(), Bytes("msg"), absl::MakeSpan(sig)));

  ASSERT_OK_AND_ASSIGN(auto verifier, NewMlDsaVerifier(pub_, &mech));
  EXPECT_THAT(verifier->Verify(client_.get(), Bytes("msg"), sig),
              StatusRvIs(CKR_SIGNATURE_INVALID));
}

TEST_P(MlDsaTest, VerifyWithContext) {
  // Cloud KMS signs with an empty context, so a verifier configured with a
  // non-empty context must reject the signature.
  CK_MECHANISM mech{CKM_ML_DSA, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(auto signer, NewMlDsaSigner(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->Sign(client_.get(), Bytes("msg"), absl::MakeSpan(sig)));

  uint8_t ctx[] = {'c', 't', 'x'};
  CK_SIGN_ADDITIONAL_CONTEXT params{CKH_HEDGE_PREFERRED, ctx, sizeof(ctx)};
  CK_MECHANISM ctx_mech{CKM_ML_DSA, &params, sizeof(params)};
  ASSERT_OK_AND_ASSIGN(auto verifier, NewMlDsaVerifier(pub_, &ctx_mech));
  EXPECT_THAT(verifier->Verify(client_.get(), Bytes("msg"), sig),
              StatusRvIs(CKR_SIGNATURE_INVALID));
}

TEST_P(MlDsaTest, SignerRejectsDeterministic) {
  CK_SIGN_ADDITIONAL_CONTEXT params{CKH_DETERMINISTIC_REQUIRED, nullptr, 0};
  CK_MECHANISM mech{CKM_ML_DSA, &params, sizeof(params)};
  EXPECT_THAT(NewMlDsaSigner(prv_, &mech),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST_P(MlDsaTest, SignerRejectsContext) {
  uint8_t ctx[] = {'c'};
  CK_SIGN_ADDITIONAL_CONTEXT params{CKH_HEDGE_PREFERRED, ctx, sizeof(ctx)};
  CK_MECHANISM mech{CKM_ML_DSA, &params, sizeof(params)};
  EXPECT_THAT(NewMlDsaSigner(prv_, &mech),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST_P(MlDsaTest, SignerRejectsBadParamSize) {
  CK_ULONG bogus = 0;
  CK_MECHANISM mech{CKM_ML_DSA, &bogus, sizeof(bogus)};
  EXPECT_THAT(NewMlDsaSigner(prv_, &mech),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST_P(MlDsaTest, SignerRejectsUnknownHedge) {
  CK_SIGN_ADDITIONAL_CONTEXT params{0x42, nullptr, 0};
  CK_MECHANISM mech{CKM_ML_DSA, &params, sizeof(params)};
  EXPECT_THAT(NewMlDsaSigner(prv_, &mech),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST_P(MlDsaTest, SignerRejectsPublicKey) {
  CK_MECHANISM mech{CKM_ML_DSA, nullptr, 0};
  EXPECT_THAT(NewMlDsaSigner(pub_, &mech),
              StatusRvIs(CKR_KEY_FUNCTION_NOT_PERMITTED));
}

TEST_P(MlDsaTest, VerifierRejectsPrivateKey) {
  CK_MECHANISM mech{CKM_ML_DSA, nullptr, 0};
  EXPECT_THAT(NewMlDsaVerifier(prv_, &mech),
              StatusRvIs(CKR_KEY_FUNCTION_NOT_PERMITTED));
}

TEST(MlDsaKeyTypeTest, SignerRejectsRsaKey) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);
  CK_MECHANISM mech{CKM_ML_DSA, nullptr, 0};
  EXPECT_THAT(NewMlDsaSigner(key, &mech),
              StatusRvIs(CKR_KEY_TYPE_INCONSISTENT));
}

}  // namespace
}  // namespace cloud_kms::kmsp11
