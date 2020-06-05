#include "kmsp11/util/kms_client.h"

#include "absl/time/time.h"
#include "gmock/gmock.h"
#include "kmsp11/test/fakekms/cpp/fakekms.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/crypto_utils.h"

namespace kmsp11 {
namespace {

class KmsClientTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_kms_, FakeKms::New());
    client_ = absl::make_unique<KmsClient>(fake_kms_->listen_addr(),
                                           grpc::InsecureChannelCredentials(),
                                           absl::Milliseconds(500));
  }
  std::unique_ptr<KmsClient> client_;

 private:
  std::unique_ptr<FakeKms> fake_kms_;
};

TEST_F(KmsClientTest, ListCryptoKeysSuccess) {
  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client_->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck1;
  ck1.set_purpose(kms_v1::CryptoKey_CryptoKeyPurpose_ENCRYPT_DECRYPT);
  ck1 = CreateCryptoKeyOrDie(client_->kms_stub(), kr.name(), "ck1", ck1, true);

  kms_v1::CryptoKey ck2;
  ck2.set_purpose(kms_v1::CryptoKey_CryptoKeyPurpose_ASYMMETRIC_DECRYPT);
  ck2.mutable_version_template()->set_algorithm(
      kms_v1::
          CryptoKeyVersion_CryptoKeyVersionAlgorithm_RSA_DECRYPT_OAEP_2048_SHA256);
  ck2 = CreateCryptoKeyOrDie(client_->kms_stub(), kr.name(), "ck2", ck2, true);

  kms_v1::ListCryptoKeysRequest list_req;
  list_req.set_parent(kr.name());
  CryptoKeysRange range = client_->ListCryptoKeys(list_req);

  CryptoKeysRange::iterator it = range.begin();
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKey rck1, *it);
  EXPECT_THAT(rck1, EqualsProto(ck1));

  it++;
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKey rck2, *it);
  EXPECT_THAT(rck2, EqualsProto(ck2));

  it++;
  EXPECT_EQ(it, range.end());
}

TEST_F(KmsClientTest, ListCryptoKeysFailureInvalidName) {
  kms_v1::ListCryptoKeysRequest list_req;
  list_req.set_parent("foo");
  CryptoKeysRange range = client_->ListCryptoKeys(list_req);

  CryptoKeysRange::iterator it = range.begin();
  EXPECT_THAT(*it, StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace kmsp11
