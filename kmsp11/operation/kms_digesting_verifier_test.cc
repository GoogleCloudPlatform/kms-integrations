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

#include "kmsp11/operation/kms_digesting_verifier.h"

#include "fakekms/cpp/fakekms.h"
#include "kmsp11/object.h"
#include "kmsp11/operation/kms_digesting_signer.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/crypto_utils.h"

namespace kmsp11 {
namespace {

using ::testing::AllOf;

class MockVerifier : public VerifierInterface {
 public:
  Object* object() override { return nullptr; };

  absl::Status Verify(KmsClient* client, absl::Span<const uint8_t> digest,
                      absl::Span<const uint8_t> signature) override {
    return absl::OkStatus();
  };
  absl::Status VerifyUpdate(KmsClient* client,
                            absl::Span<const uint8_t> data) override {
    return absl::OkStatus();
  };
  absl::Status VerifyFinal(KmsClient* client,
                           absl::Span<const uint8_t> signature) override {
    return absl::OkStatus();
  };

  virtual ~MockVerifier() {}
};

class KmsDigestingVerifierTest : public testing::Test {
 protected:
  void SetUp(google::cloud::kms::v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm
                 algorithm) {
    ASSERT_OK_AND_ASSIGN(fake_server_, fakekms::Server::New());
    client_ = std::make_unique<KmsClient>(fake_server_->listen_addr(),
                                          grpc::InsecureChannelCredentials(),
                                          absl::Seconds(1));

    auto fake_client = fake_server_->NewClient();

    kms_v1::KeyRing kr;
    kr = CreateKeyRingOrDie(fake_client.get(), kTestLocation, RandomId(), kr);

    kms_v1::CryptoKey ck;
    ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
    ck.mutable_version_template()->set_algorithm(algorithm);
    ck = CreateCryptoKeyOrDie(fake_client.get(), kr.name(), "ck", ck, true);

    kms_v1::CryptoKeyVersion ckv;
    ckv = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv);
    ckv = WaitForEnablement(fake_client.get(), ckv);

    kms_key_name_ = ckv.name();

    kms_v1::PublicKey pub_proto = GetPublicKey(fake_client.get(), ckv);
    ASSERT_OK_AND_ASSIGN(public_key_, ParseX509PublicKeyPem(pub_proto.pem()));

    ASSERT_OK_AND_ASSIGN(KeyPair kp,
                         Object::NewKeyPair(ckv, public_key_.get()));
    pub_ = std::make_shared<Object>(kp.public_key);
    prv_ = std::make_shared<Object>(kp.private_key);
  }

  std::unique_ptr<fakekms::Server> fake_server_;
  std::unique_ptr<KmsClient> client_;
  std::string kms_key_name_;
  bssl::UniquePtr<EVP_PKEY> public_key_;
  std::shared_ptr<Object> pub_, prv_;
};

TEST_F(KmsDigestingVerifierTest, VerifyFinalWithoutUpdateFails) {
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};

  CK_MECHANISM mech{CKM_ECDSA_SHA256, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<VerifierInterface> verifier,
      KmsDigestingVerifier::New(
          nullptr, std::unique_ptr<VerifierInterface>(new MockVerifier()),
          &mech));
  std::vector<uint8_t> sig(98);
  EXPECT_THAT(verifier->VerifyFinal(client_.get(), absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_F(KmsDigestingVerifierTest, VerifySinglePartAfterUpdateFails) {
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};

  CK_MECHANISM mech{CKM_ECDSA_SHA256, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<VerifierInterface> verifier,
      KmsDigestingVerifier::New(
          nullptr, std::unique_ptr<VerifierInterface>(new MockVerifier()),
          &mech));
  std::vector<uint8_t> sig(98);
  EXPECT_OK(verifier->VerifyUpdate(client_.get(), data));
  EXPECT_THAT(verifier->Verify(client_.get(), data, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_F(KmsDigestingVerifierTest, RsaPkcs1SignVerifySuccess) {
  SetUp(kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256);
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};

  CK_MECHANISM mech{CKM_SHA256_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       KmsDigestingSigner::New(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->Sign(client_.get(), data, absl::MakeSpan(sig)));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       KmsDigestingVerifier::New(pub_, &mech));
  EXPECT_OK(verifier->Verify(client_.get(), data, absl::MakeSpan(sig)));
}

TEST_F(KmsDigestingVerifierTest, RsaRawPkcs1VerifyMultiPartSuccess) {
  SetUp(kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_2048);

  CK_MECHANISM mech{CKM_SHA256_RSA_PKCS, nullptr, 0};
  uint8_t data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       KmsDigestingSigner::New(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->Sign(client_.get(), data, absl::MakeSpan(sig)));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       KmsDigestingVerifier::New(pub_, &mech));
  EXPECT_OK(
      verifier->VerifyUpdate(client_.get(), absl::MakeConstSpan(&data[0], 2)));
  EXPECT_OK(
      verifier->VerifyUpdate(client_.get(), absl::MakeConstSpan(&data[2], 2)));
  EXPECT_OK(verifier->VerifyFinal(client_.get(), absl::MakeSpan(sig)));
}

}  // namespace
}  // namespace kmsp11
