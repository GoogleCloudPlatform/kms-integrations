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

#include "common/kms_client.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "kmsp11/object_loader.h"
#include "kmsp11/object_store.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/ml_dsa_fake_kms.h"
#include "kmsp11/util/ml_dsa.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

constexpr std::string_view kKeyRing =
    "projects/foo/locations/global/keyRings/bar";

class ObjectLoaderMlDsaTest : public testing::Test {
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
  }

  std::unique_ptr<MlDsaFakeKms> fake_;
  std::unique_ptr<KmsClient> client_;
};

TEST_F(ObjectLoaderMlDsaTest, LoadsMlDsaKeysWithNistPqcPublicKeys) {
  ASSERT_OK_AND_ASSIGN(
      kms_v1::CryptoKeyVersion ckv44,
      fake_->CreateKey(kKeyRing, "k44",
                       kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_44));
  ASSERT_OK_AND_ASSIGN(
      kms_v1::CryptoKeyVersion ckv65,
      fake_->CreateKey(kKeyRing, "k65",
                       kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_65));
  ASSERT_OK_AND_ASSIGN(
      kms_v1::CryptoKeyVersion ckv87,
      fake_->CreateKey(kKeyRing, "k87",
                       kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_87));

  // generate_certs is enabled to ensure it is skipped for ML-DSA keys rather
  // than causing a failure.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader,
                       ObjectLoader::New(kKeyRing, {}, true));
  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader->BuildState(*client_));
  ASSERT_EQ(state.keys_size(), 3);

  for (const Key& key : state.keys()) {
    EXPECT_FALSE(key.has_certificate());
    ASSERT_OK_AND_ASSIGN(MlDsaPublicKey pub,
                         ParseMlDsaPublicKeyDer(key.public_key_der()));
    ASSERT_OK_AND_ASSIGN(
        CK_ML_DSA_PARAMETER_SET_TYPE want,
        MlDsaParameterSetForAlgorithm(key.crypto_key_version().algorithm()));
    EXPECT_EQ(pub.parameter_set, want);
  }

  // The state must round-trip into an ObjectStore.
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectStore> store,
                       ObjectStore::New(state));
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> prv,
                       store->GetKey(state.keys(1).private_key_handle()));
  EXPECT_EQ(prv->algorithm().key_type, CKK_ML_DSA);
  EXPECT_EQ(prv->object_class(), CKO_PRIVATE_KEY);
}

}  // namespace
}  // namespace cloud_kms::kmsp11
