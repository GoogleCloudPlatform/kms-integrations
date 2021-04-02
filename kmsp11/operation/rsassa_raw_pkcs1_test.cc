#include "kmsp11/operation/rsassa_raw_pkcs1.h"

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
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_2048,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  char buf[1];
  CK_MECHANISM mechanism{CKM_RSA_PKCS, buf, sizeof(buf)};
  EXPECT_THAT(RsaRawPkcs1Signer::New(key, &mechanism),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST(NewSignerTest, KeyTypeInconsistentWhenEcKeyIsSupplied) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp, NewMockKeyPair(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                                 "ec_p256_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  CK_MECHANISM mechanism{CKM_RSA_PKCS, nullptr, 0};
  EXPECT_THAT(RsaRawPkcs1Signer::New(key, &mechanism),
              StatusRvIs(CKR_KEY_TYPE_INCONSISTENT));
}

TEST(NewSignerTest, KeyFunctionNotPermittedWhenPublicKeyIsSupplied) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_2048,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.public_key);

  CK_MECHANISM mechanism{CKM_RSA_PKCS, nullptr, 0};
  EXPECT_THAT(RsaRawPkcs1Signer::New(key, &mechanism),
              StatusRvIs(CKR_KEY_FUNCTION_NOT_PERMITTED));
}

TEST(NewVerifierTest, AnySuppliedParamIsInvalid) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_2048,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.public_key);

  char buf[1];
  CK_MECHANISM mechanism{CKM_RSA_PKCS, buf, sizeof(buf)};
  EXPECT_THAT(RsaRawPkcs1Verifier::New(key, &mechanism),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST(NewVerifierTest, KeyTypeInconsistentWhenEcKeyIsSupplied) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp, NewMockKeyPair(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                                 "ec_p256_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.public_key);

  CK_MECHANISM mechanism{CKM_RSA_PKCS, nullptr, 0};
  EXPECT_THAT(RsaRawPkcs1Verifier::New(key, &mechanism),
              StatusRvIs(CKR_KEY_TYPE_INCONSISTENT));
}

TEST(NewVerifierTest, KeyFunctionNotPermittedWhenPrivateKeyIsSupplied) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_2048,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  CK_MECHANISM mechanism{CKM_RSA_PKCS, nullptr, 0};
  EXPECT_THAT(RsaRawPkcs1Verifier::New(key, &mechanism),
              StatusRvIs(CKR_KEY_FUNCTION_NOT_PERMITTED));
}

class RsaRawPkcs1Test : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_server_, fakekms::Server::New());
    client_ = absl::make_unique<KmsClient>(fake_server_->listen_addr(),
                                           grpc::InsecureChannelCredentials(),
                                           absl::Seconds(1));

    auto fake_client = fake_server_->NewClient();

    kms_v1::KeyRing kr;
    kr = CreateKeyRingOrDie(fake_client.get(), kTestLocation, RandomId(), kr);

    kms_v1::CryptoKey ck;
    ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
    ck.mutable_version_template()->set_algorithm(
        kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_2048);
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

TEST_F(RsaRawPkcs1Test, SignSuccess) {
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       RsaRawPkcs1Signer::New(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->Sign(client_.get(), data, absl::MakeSpan(sig)));

  EXPECT_OK(RsaVerifyRawPkcs1(EVP_PKEY_get0_RSA(public_key_.get()), data, sig));
}

TEST_F(RsaRawPkcs1Test, SignDataLengthInvalid) {
  uint8_t data[246], sig[256];

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       RsaRawPkcs1Signer::New(prv_, &mech));

  EXPECT_THAT(signer->Sign(client_.get(), data, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_DATA_LEN_RANGE)));
}

TEST_F(RsaRawPkcs1Test, SignSignatureLengthInvalid) {
  uint8_t data[32], sig[255];

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       RsaRawPkcs1Signer::New(prv_, &mech));

  EXPECT_THAT(signer->Sign(client_.get(), data, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInternal),
                    StatusRvIs(CKR_GENERAL_ERROR)));
}

TEST_F(RsaRawPkcs1Test, SignVerifySuccess) {
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       RsaRawPkcs1Signer::New(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->Sign(client_.get(), data, absl::MakeSpan(sig)));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       RsaRawPkcs1Verifier::New(pub_, &mech));
  EXPECT_OK(verifier->Verify(client_.get(), data, sig));
}

TEST_F(RsaRawPkcs1Test, VerifyDataLengthInvalid) {
  uint8_t data[246], sig[256];

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       RsaRawPkcs1Verifier::New(pub_, &mech));

  EXPECT_THAT(verifier->Verify(client_.get(), data, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_DATA_LEN_RANGE)));
}

TEST_F(RsaRawPkcs1Test, VerifySignatureLengthInvalid) {
  uint8_t data[32], sig[255];

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       RsaRawPkcs1Verifier::New(pub_, &mech));

  EXPECT_THAT(verifier->Verify(client_.get(), data, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_SIGNATURE_LEN_RANGE)));
}

TEST_F(RsaRawPkcs1Test, VerifyBadSignature) {
  uint8_t data[32], sig[256];

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       RsaRawPkcs1Verifier::New(pub_, &mech));

  EXPECT_THAT(verifier->Verify(client_.get(), data, sig),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_SIGNATURE_INVALID)));
}

}  // namespace
}  // namespace kmsp11
