#include "kmsp11/operation/rsaes_oaep.h"

#include "gmock/gmock.h"
#include "kmsp11/object.h"
#include "kmsp11/test/fakekms/cpp/fakekms.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/runfiles.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/kms_client.h"

namespace kmsp11 {
namespace {

static StatusOr<KeyPair> NewMockKeyPair(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
    absl::string_view public_key_runfile) {
  kms_v1::CryptoKeyVersion ckv;
  ckv.set_name(
      "projects/foo/locations/bar/keyRings/baz/cryptoKeys/qux/"
      "cryptoKeyVersions/1");
  ckv.set_algorithm(algorithm);
  ckv.set_state(kms_v1::CryptoKeyVersion::ENABLED);

  ASSIGN_OR_RETURN(std::string pub_pem, LoadTestRunfile(public_key_runfile));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> pub,
                   ParseX509PublicKeyPem(pub_pem));
  return Object::NewKeyPair(ckv, pub.get());
}

static CK_RSA_PKCS_OAEP_PARAMS NewOaepParams() {
  return CK_RSA_PKCS_OAEP_PARAMS{
      CKM_SHA256,          // hashAlg
      CKG_MGF1_SHA256,     // mgf
      CKZ_DATA_SPECIFIED,  // source
      nullptr,             // pSourceData
      0,                   // ulSourceDataLen
  };
}

static CK_MECHANISM NewOaepMechanism(CK_RSA_PKCS_OAEP_PARAMS* params) {
  return CK_MECHANISM{
      CKM_RSA_PKCS_OAEP,  // mechanism
      params,             // pParameter
      sizeof(*params),    // ulParameterLen
  };
}

TEST(NewOaepDecrypterTest, Success) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  CK_RSA_PKCS_OAEP_PARAMS params = NewOaepParams();
  CK_MECHANISM mechanism = NewOaepMechanism(&params);

  EXPECT_OK(RsaOaepDecrypter::New(key, &mechanism));
}

TEST(NewOaepDecrypterTest, FailureWrongKeyType) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp, NewMockKeyPair(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                                 "ec_p256_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  CK_RSA_PKCS_OAEP_PARAMS params = NewOaepParams();
  CK_MECHANISM mechanism = NewOaepMechanism(&params);

  EXPECT_THAT(RsaOaepDecrypter::New(key, &mechanism),
              StatusRvIs(CKR_KEY_TYPE_INCONSISTENT));
}

TEST(NewOaepDecrypterTest, FailureWrongObjectClass) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.public_key);

  CK_RSA_PKCS_OAEP_PARAMS params = NewOaepParams();
  CK_MECHANISM mechanism = NewOaepMechanism(&params);

  EXPECT_THAT(RsaOaepDecrypter::New(key, &mechanism),
              StatusRvIs(CKR_KEY_FUNCTION_NOT_PERMITTED));
}

TEST(NewOaepDecrypterTest, FailureMechanismNotAllowed) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  CK_RSA_PKCS_OAEP_PARAMS params = NewOaepParams();
  CK_MECHANISM mechanism = NewOaepMechanism(&params);

  EXPECT_THAT(RsaOaepDecrypter::New(key, &mechanism),
              StatusRvIs(CKR_KEY_FUNCTION_NOT_PERMITTED));
}

class OaepDecryptTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_kms_, FakeKms::New());
    client_ = absl::make_unique<KmsClient>(fake_kms_->listen_addr(),
                                           grpc::InsecureChannelCredentials(),
                                           absl::Seconds(1));

    auto fake_client = fake_kms_->NewClient();

    kms_v1::KeyRing kr;
    kr = CreateKeyRingOrDie(fake_client.get(), kTestLocation, RandomId(), kr);

    kms_v1::CryptoKey ck;
    ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
    ck.mutable_version_template()->set_algorithm(
        kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
    ck = CreateCryptoKeyOrDie(fake_client.get(), kr.name(), "ck", ck, true);

    kms_v1::CryptoKeyVersion ckv;
    ckv = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv);
    ckv = WaitForEnablement(fake_client.get(), ckv);

    kms_key_name_ = ckv.name();

    kms_v1::PublicKey pub_proto = GetPublicKey(fake_client.get(), ckv);
    ASSERT_OK_AND_ASSIGN(public_key_, ParseX509PublicKeyPem(pub_proto.pem()));

    ASSERT_OK_AND_ASSIGN(KeyPair kp,
                         Object::NewKeyPair(ckv, public_key_.get()));
    std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

    CK_RSA_PKCS_OAEP_PARAMS params = NewOaepParams();
    CK_MECHANISM mechanism = NewOaepMechanism(&params);

    ASSERT_OK_AND_ASSIGN(decrypter_, RsaOaepDecrypter::New(key, &mechanism));
  }

  std::unique_ptr<FakeKms> fake_kms_;
  std::unique_ptr<KmsClient> client_;
  std::string kms_key_name_;
  bssl::UniquePtr<EVP_PKEY> public_key_;
  std::unique_ptr<DecrypterInterface> decrypter_;
};

TEST_F(OaepDecryptTest, DecryptSuccess) {
  std::vector<uint8_t> plaintext = {0xDE, 0xAD, 0xBE, 0xEF};
  uint8_t ciphertext[256];

  EXPECT_OK(EncryptRsaOaep(public_key_.get(), EVP_sha256(), plaintext,
                           absl::MakeSpan(ciphertext)));

  ASSERT_OK_AND_ASSIGN(absl::Span<const uint8_t> recovered_plaintext,
                       decrypter_->Decrypt(client_.get(), ciphertext));

  EXPECT_EQ(recovered_plaintext, plaintext);
}

TEST_F(OaepDecryptTest, DecryptFailureBadCiphertextSize) {
  uint8_t ciphertext[255];
  EXPECT_THAT(decrypter_->Decrypt(client_.get(), ciphertext),
              StatusRvIs(CKR_ENCRYPTED_DATA_LEN_RANGE));
}

TEST_F(OaepDecryptTest, DecryptFailureCiphertextInvalid) {
  uint8_t ciphertext[256];
  EXPECT_THAT(decrypter_->Decrypt(client_.get(), ciphertext),
              StatusRvIs(CKR_ENCRYPTED_DATA_INVALID));
}

TEST_F(OaepDecryptTest, DecryptFailureKeyDisabled) {
  kms_v1::CryptoKeyVersion ckv;
  ckv.set_name(kms_key_name_);
  ckv.set_state(kms_v1::CryptoKeyVersion::DISABLED);

  google::protobuf::FieldMask update_mask;
  update_mask.add_paths("state");

  UpdateCryptoKeyVersionOrDie(fake_kms_->NewClient().get(), ckv, update_mask);

  uint8_t ciphertext[256];
  EXPECT_THAT(decrypter_->Decrypt(client_.get(), ciphertext),
              StatusRvIs(CKR_DEVICE_ERROR));
}

}  // namespace
}  // namespace kmsp11