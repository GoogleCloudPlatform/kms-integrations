#include "kmsp11/session.h"

#include "gmock/gmock.h"
#include "kmsp11/test/fakekms/cpp/fakekms.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/crypto_utils.h"

namespace kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::IsEmpty;
using ::testing::Pointee;
using ::testing::Property;

class SessionTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_kms_, FakeKms::New());

    auto fake_client = fake_kms_->NewClient();
    key_ring_ = CreateKeyRingOrDie(fake_client.get(), kTestLocation, RandomId(),
                                   key_ring_);

    config_.set_key_ring(key_ring_.name());
    client_ = absl::make_unique<KmsClient>(fake_kms_->listen_addr(),
                                           grpc::InsecureChannelCredentials(),
                                           absl::Seconds(1));
  }

  std::unique_ptr<FakeKms> fake_kms_;
  kms_v1::KeyRing key_ring_;
  TokenConfig config_;
  std::unique_ptr<KmsClient> client_;
};

TEST_F(SessionTest, FindEmptyTokenSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), client_.get());

  EXPECT_OK(s.FindObjectsInit(std::vector<CK_ATTRIBUTE>()));
  EXPECT_THAT(s.FindObjects(1), IsOkAndHolds(IsEmpty()));
  EXPECT_OK(s.FindObjectsFinal());
}

TEST_F(SessionTest, FindAllSinglePage) {
  auto kms_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey_CryptoKeyPurpose_ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion_CryptoKeyVersionAlgorithm_EC_SIGN_P384_SHA384);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), client_.get());

  EXPECT_OK(s.FindObjectsInit(std::vector<CK_ATTRIBUTE>()));
  ASSERT_OK_AND_ASSIGN(absl::Span<const CK_OBJECT_HANDLE> handles,
                       s.FindObjects(5));
  EXPECT_EQ(handles.size(), 2);

  EXPECT_THAT(
      token->GetObject(handles[0]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv.name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));

  EXPECT_THAT(
      token->GetObject(handles[1]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv.name()),
          Property("object_class", &Object::object_class, CKO_PRIVATE_KEY)))));

  EXPECT_OK(s.FindObjectsFinal());
}

TEST_F(SessionTest, FindIgnoreResults) {
  auto kms_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey_CryptoKeyPurpose_ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion_CryptoKeyVersionAlgorithm_EC_SIGN_P384_SHA384);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), client_.get());

  EXPECT_OK(s.FindObjectsInit(std::vector<CK_ATTRIBUTE>()));
  EXPECT_OK(s.FindObjectsFinal());
}

TEST_F(SessionTest, FindPublicKeysMultiPage) {
  auto kms_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey_CryptoKeyPurpose_ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion_CryptoKeyVersionAlgorithm_EC_SIGN_P384_SHA384);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv1;
  ckv1 = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv1);
  ckv1 = WaitForEnablement(kms_client.get(), ckv1);

  kms_v1::CryptoKeyVersion ckv2;
  ckv2 = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv2);
  ckv2 = WaitForEnablement(kms_client.get(), ckv2);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), client_.get());

  CK_OBJECT_CLASS want_class = CKO_PUBLIC_KEY;
  std::vector<CK_ATTRIBUTE> attr_template = {
      {CKA_CLASS, &want_class, sizeof(want_class)},
  };

  EXPECT_OK(s.FindObjectsInit(attr_template));

  ASSERT_OK_AND_ASSIGN(absl::Span<const CK_OBJECT_HANDLE> handles,
                       s.FindObjects(1));
  EXPECT_EQ(handles.size(), 1);
  EXPECT_THAT(
      token->GetObject(handles[0]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv1.name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));

  ASSERT_OK_AND_ASSIGN(handles, s.FindObjects(1));
  EXPECT_EQ(handles.size(), 1);
  EXPECT_THAT(
      token->GetObject(handles[0]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv2.name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));

  ASSERT_OK_AND_ASSIGN(handles, s.FindObjects(1));
  EXPECT_EQ(handles.size(), 0);

  EXPECT_OK(s.FindObjectsFinal());
}

TEST_F(SessionTest, FindInitAlreadyActive) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), client_.get());

  EXPECT_OK(s.FindObjectsInit(std::vector<CK_ATTRIBUTE>()));

  EXPECT_THAT(s.FindObjectsInit(std::vector<CK_ATTRIBUTE>()),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(SessionTest, FindNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), client_.get());

  EXPECT_THAT(s.FindObjects(1), StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, FindFinalNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), client_.get());

  EXPECT_THAT(s.FindObjectsFinal(), StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, Decrypt) {
  auto kms_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  kms_v1::PublicKey pub_proto = GetPublicKey(kms_client.get(), ckv);
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub,
                       ParseX509PublicKeyPem(pub_proto.pem()));

  std::vector<uint8_t> plaintext = {0x00, 0x01, 0xFE, 0xFF};
  uint8_t ciphertext[256];
  EXPECT_OK(EncryptRsaOaep(pub.get(), EVP_sha256(), plaintext,
                           absl::MakeSpan(ciphertext)));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_PRIVATE_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> object,
                       s.token()->GetObject(handles[0]));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(s.DecryptInit(object, &mech));
  EXPECT_THAT(s.Decrypt(ciphertext), IsOkAndHolds(plaintext));
}

TEST_F(SessionTest, DecryptInitAlreadyActive) {
  auto kms_client = fake_kms_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_PRIVATE_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> object,
                       s.token()->GetObject(handles[0]));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(s.DecryptInit(object, &mech))
  EXPECT_THAT(s.DecryptInit(object, &mech), StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(SessionTest, DecryptNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), client_.get());

  uint8_t ciphertext[32];
  EXPECT_THAT(s.Decrypt(ciphertext), StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

}  // namespace
}  // namespace kmsp11