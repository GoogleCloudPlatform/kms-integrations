// Copyright 2022 Google LLC
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

#include "kmsp11/operation/hmac.h"

#include "fakekms/cpp/fakekms.h"
#include "kmsp11/object.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/crypto_utils.h"

namespace kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::HasSubstr;

TEST(NewSignerTest, AnySuppliedParamIsInvalid) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::HMAC_SHA256));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  char buf[1];
  CK_MECHANISM mechanism{CKM_SHA256_HMAC, buf, sizeof(buf)};
  EXPECT_THAT(NewHmacSigner(key, &mechanism),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST(NewSignerTest, KeyTypeInconsistentWhenSha1KeyIsSupplied) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::HMAC_SHA1));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  CK_MECHANISM mechanism{CKM_SHA256_HMAC, nullptr, 0};
  EXPECT_THAT(NewHmacSigner(key, &mechanism),
              StatusRvIs(CKR_KEY_TYPE_INCONSISTENT));
}

class HmacTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_server_, fakekms::Server::New());
    client_ = std::make_unique<KmsClient>(fake_server_->listen_addr(),
                                          grpc::InsecureChannelCredentials(),
                                          absl::Seconds(1));

    auto fake_client = fake_server_->NewClient();

    kms_v1::KeyRing kr;
    kr = CreateKeyRingOrDie(fake_client.get(), kTestLocation, RandomId(), kr);

    kms_v1::CryptoKey ck;
    ck.set_purpose(kms_v1::CryptoKey::MAC);
    ck.mutable_version_template()->set_algorithm(
        kms_v1::CryptoKeyVersion::HMAC_SHA256);
    ck = CreateCryptoKeyOrDie(fake_client.get(), kr.name(), "ck", ck, true);

    kms_v1::CryptoKeyVersion ckv;
    ckv = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv);
    ckv = WaitForEnablement(fake_client.get(), ckv);

    kms_key_name_ = ckv.name();

    ASSERT_OK_AND_ASSIGN(Object key, Object::NewSecretKey(ckv));
    prv_ = std::make_shared<Object>(key);
  }

  std::unique_ptr<fakekms::Server> fake_server_;
  std::unique_ptr<KmsClient> client_;
  std::string kms_key_name_;
  std::shared_ptr<Object> prv_;
};

TEST_F(HmacTest, SignSuccess) {
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       NewHmacSigner(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->Sign(client_.get(), data, absl::MakeSpan(sig)));
}

TEST_F(HmacTest, SignDataLengthInvalid) {
  uint8_t data[65537], sig[32];

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       NewHmacSigner(prv_, &mech));

  EXPECT_THAT(signer->Sign(client_.get(), data, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_DATA_LEN_RANGE)));
}

TEST_F(HmacTest, SignSignatureLengthInvalid) {
  uint8_t data[65536], sig[33];

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       NewHmacSigner(prv_, &mech));

  EXPECT_THAT(signer->Sign(client_.get(), data, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInternal),
                    StatusRvIs(CKR_GENERAL_ERROR)));
}

}  // namespace
}  // namespace kmsp11
