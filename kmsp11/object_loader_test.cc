#include "kmsp11/object_loader.h"

#include "gmock/gmock.h"
#include "kmsp11/test/fakekms/cpp/fakekms.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/crypto_utils.h"

namespace kmsp11 {
namespace {

using ::testing::ElementsAre;
using ::testing::Property;

class BuildStateTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_kms_, FakeKms::New());

    kms_stub_ = fake_kms_->NewClient();
    key_ring_ = CreateKeyRingOrDie(kms_stub_.get(), kTestLocation, RandomId(),
                                   key_ring_);

    client_ = absl::make_unique<KmsClient>(fake_kms_->listen_addr(),
                                           grpc::InsecureChannelCredentials(),
                                           absl::Seconds(1));
  }

  kms_v1::CryptoKeyVersion AddKeyAndInitialVersion(
      absl::string_view key_name, kms_v1::CryptoKey::CryptoKeyPurpose purpose,
      kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
      kms_v1::ProtectionLevel protection_level = kms_v1::HSM) {
    kms_v1::CryptoKey ck;
    ck.set_purpose(purpose);
    ck.mutable_version_template()->set_algorithm(algorithm);
    ck.mutable_version_template()->set_protection_level(protection_level);
    ck = CreateCryptoKeyOrDie(kms_stub_.get(), key_ring_.name(), key_name, ck,
                              true);

    kms_v1::CryptoKeyVersion ckv;
    ckv = CreateCryptoKeyVersionOrDie(kms_stub_.get(), ck.name(), ckv);
    return WaitForEnablement(kms_stub_.get(), ckv);
  }

  std::unique_ptr<FakeKms> fake_kms_;
  std::unique_ptr<kms_v1::KeyManagementService::Stub> kms_stub_;
  kms_v1::KeyRing key_ring_;
  std::unique_ptr<KmsClient> client_;
};

TEST_F(BuildStateTest, EmptyKeyRingReturnsEmptyState) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), true));

  EXPECT_THAT(loader_->BuildState(*client_),
              IsOkAndHolds(EqualsProto(ObjectStoreState())));
}

TEST_F(BuildStateTest, OutputContainsVersionProto) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));

  EXPECT_THAT(state.asymmetric_keys(),
              ElementsAre(Property("crypto_key_version",
                                   &AsymmetricKey::crypto_key_version,
                                   EqualsProto(ckv))));
}

TEST_F(BuildStateTest, OutputContainsGeneratedHandles) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  ASSERT_EQ(state.asymmetric_keys_size(), 1);

  EXPECT_GT(state.asymmetric_keys(0).private_key_handle(), 0);
  EXPECT_GT(state.asymmetric_keys(0).public_key_handle(), 0);
}

TEST_F(BuildStateTest, OutputContainsPublicKey) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  ASSERT_EQ(state.asymmetric_keys_size(), 1);

  EXPECT_OK(ParseX509PublicKeyDer(state.asymmetric_keys(0).public_key_der()));
}

TEST_F(BuildStateTest, OutputContainsCertificateWhenCertsAreEnabled) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  ASSERT_EQ(state.asymmetric_keys_size(), 1);

  EXPECT_TRUE(state.asymmetric_keys(0).has_certificate());
  EXPECT_GT(state.asymmetric_keys(0).certificate().handle(), 0);
  EXPECT_OK(ParseX509CertificateDer(
      state.asymmetric_keys(0).certificate().x509_der()));
}

TEST_F(BuildStateTest, OutputContainsNoCertificateWhenCertsAreDisabled) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), false));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  ASSERT_EQ(state.asymmetric_keys_size(), 1);

  EXPECT_FALSE(state.asymmetric_keys(0).has_certificate());
}

TEST_F(BuildStateTest, UnmodifiedStateIsUnchangedAfterRefresh) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  EXPECT_THAT(loader_->BuildState(*client_), IsOkAndHolds(EqualsProto(state)));
}

TEST_F(BuildStateTest, PreviouslyRetrievedStateIsUnchangedAfterElementIsAdded) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), true));
  kms_v1::CryptoKeyVersion ckv1 =
      AddKeyAndInitialVersion("ck1", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ASSERT_OK_AND_ASSIGN(ObjectStoreState original_state,
                       loader_->BuildState(*client_));
  ASSERT_EQ(original_state.asymmetric_keys_size(), 1);

  kms_v1::CryptoKeyVersion ckv2 = AddKeyAndInitialVersion(
      "ck2", kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ASSERT_OK_AND_ASSIGN(ObjectStoreState updated_state,
                       loader_->BuildState(*client_));

  EXPECT_THAT(
      updated_state.asymmetric_keys(),
      ElementsAre(
          // The first element matches the previously retrieved result exactly.
          EqualsProto(original_state.asymmetric_keys(0)),
          // The second element refers to the newly added key.
          Property("crypto_key_version", &AsymmetricKey::crypto_key_version,
                   EqualsProto(ckv2))));
}

TEST_F(BuildStateTest, KeyWithPurposeEncryptDecryptIsOmitted) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), true));
  kms_v1::CryptoKeyVersion ckv = AddKeyAndInitialVersion(
      "ck", kms_v1::CryptoKey::ENCRYPT_DECRYPT,
      kms_v1::CryptoKeyVersion::GOOGLE_SYMMETRIC_ENCRYPTION);

  EXPECT_THAT(loader_->BuildState(*client_),
              IsOkAndHolds(EqualsProto(ObjectStoreState())));
}

TEST_F(BuildStateTest, KeyWithSoftwareProtectionLevelIsOmitted) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                              kms_v1::ProtectionLevel::SOFTWARE);

  EXPECT_THAT(loader_->BuildState(*client_),
              IsOkAndHolds(EqualsProto(ObjectStoreState())));
}

TEST_F(BuildStateTest, VersionWithStateDisabledIsOmitted) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ckv.set_state(kms_v1::CryptoKeyVersion::DISABLED);
  google::protobuf::FieldMask update_mask;
  update_mask.add_paths("state");
  ckv = UpdateCryptoKeyVersionOrDie(kms_stub_.get(), ckv, update_mask);

  EXPECT_THAT(loader_->BuildState(*client_),
              IsOkAndHolds(EqualsProto(ObjectStoreState())));
}

TEST_F(BuildStateTest, VersionWithAlgorithmP224IsOmitted) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), true));
  kms_v1::CryptoKeyVersion ckv = AddKeyAndInitialVersion(
      "ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
      kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm(
          /* EC_SIGN_P224_SHA256 */ 11));

  EXPECT_THAT(loader_->BuildState(*client_),
              IsOkAndHolds(EqualsProto(ObjectStoreState())));
}

}  // namespace
}  // namespace kmsp11
