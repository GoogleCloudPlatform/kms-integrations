#include "kmsp11/operation/rsassa_pkcs1.h"

#include "fakekms/cpp/fakekms.h"
#include "kmsp11/object.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/crypto_utils.h"

namespace kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::HasSubstr;

// Build a DigestInfo structure, which is the expected input into a CKM_RSA_PKCS
// signing operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850410
absl::StatusOr<std::vector<uint8_t>> BuildRsaDigestInfo(
    int digest_nid, absl::Span<const uint8_t> digest) {
  X509_ALGOR* algorithm;
  ASN1_OCTET_STRING* dig;
  bssl::UniquePtr<X509_SIG> digest_info(X509_SIG_new());
  X509_SIG_getm(digest_info.get(), &algorithm, &dig);

  if (X509_ALGOR_set0(algorithm, OBJ_nid2obj(digest_nid), V_ASN1_NULL,
                      nullptr) != 1) {
    return absl::InternalError(absl::StrCat(
        "failure setting algorithm parameters: ", SslErrorToString()));
  }
  if (ASN1_OCTET_STRING_set(dig, digest.data(), digest.size()) != 1) {
    return absl::InternalError(
        absl::StrCat("failure setting digest value: ", SslErrorToString()));
  }

  ASSIGN_OR_RETURN(std::string digest_info_der,
                   MarshalX509Sig(digest_info.get()));
  return std::vector<uint8_t>(
      reinterpret_cast<const uint8_t*>(digest_info_der.data()),
      reinterpret_cast<const uint8_t*>(digest_info_der.data() +
                                       digest_info_der.size()));
}

TEST(NewSignerTest, ParamInvalid) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  char buf[1];
  CK_MECHANISM mechanism{CKM_RSA_PKCS, buf, sizeof(buf)};
  EXPECT_THAT(RsaPkcs1Signer::New(key, &mechanism),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST(NewSignerTest, FailureWrongKeyType) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp, NewMockKeyPair(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                                 "ec_p256_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  CK_MECHANISM mechanism{CKM_RSA_PKCS, nullptr, 0};
  EXPECT_THAT(RsaPkcs1Signer::New(key, &mechanism),
              StatusRvIs(CKR_KEY_TYPE_INCONSISTENT));
}

TEST(NewSignerTest, FailureWrongObjectClass) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.public_key);

  CK_MECHANISM mechanism{CKM_RSA_PKCS, nullptr, 0};
  EXPECT_THAT(RsaPkcs1Signer::New(key, &mechanism),
              StatusRvIs(CKR_KEY_FUNCTION_NOT_PERMITTED));
}

TEST(NewVerifierTest, ParamInvalid) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.public_key);

  char buf[1];
  CK_MECHANISM mechanism{CKM_RSA_PKCS, buf, sizeof(buf)};
  EXPECT_THAT(RsaPkcs1Verifier::New(key, &mechanism),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST(NewVerifierTest, FailureWrongKeyType) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp, NewMockKeyPair(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                                 "ec_p256_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.public_key);

  CK_MECHANISM mechanism{CKM_RSA_PKCS, nullptr, 0};
  EXPECT_THAT(RsaPkcs1Verifier::New(key, &mechanism),
              StatusRvIs(CKR_KEY_TYPE_INCONSISTENT));
}

TEST(NewVerifierTest, FailureWrongObjectClass) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  CK_MECHANISM mechanism{CKM_RSA_PKCS, nullptr, 0};
  EXPECT_THAT(RsaPkcs1Verifier::New(key, &mechanism),
              StatusRvIs(CKR_KEY_FUNCTION_NOT_PERMITTED));
}

class RsaPkcs1Test : public testing::Test {
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
    ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
    ck.mutable_version_template()->set_algorithm(
        kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256);
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

  std::unique_ptr<FakeKms> fake_kms_;
  std::unique_ptr<KmsClient> client_;
  std::string kms_key_name_;
  bssl::UniquePtr<EVP_PKEY> public_key_;
  std::shared_ptr<Object> pub_, prv_;
};

TEST_F(RsaPkcs1Test, SignSuccess) {
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
  uint8_t digest[32];
  SHA256(data.data(), data.size(), digest);
  ASSERT_OK_AND_ASSIGN(std::vector<uint8_t> digest_info,
                       BuildRsaDigestInfo(NID_sha256, digest));

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       RsaPkcs1Signer::New(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->Sign(client_.get(), digest_info, absl::MakeSpan(sig)));

  EXPECT_OK(RsaVerifyPkcs1(EVP_PKEY_get0_RSA(public_key_.get()), EVP_sha256(),
                           digest, sig));
}

TEST_F(RsaPkcs1Test, SignUnparseableDigestInfo) {
  uint8_t digest_info[48], sig[256];
  RAND_bytes(digest_info, sizeof(digest_info));

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       RsaPkcs1Signer::New(prv_, &mech));

  EXPECT_THAT(signer->Sign(client_.get(), digest_info, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                             HasSubstr("error parsing DigestInfo")),
                    StatusRvIs(CKR_DATA_INVALID)));
}

TEST_F(RsaPkcs1Test, SignWrongDigestType) {
  uint8_t digest[48], sig[256];
  ASSERT_OK_AND_ASSIGN(std::vector<uint8_t> digest_info,
                       BuildRsaDigestInfo(NID_sha384, digest));

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       RsaPkcs1Signer::New(prv_, &mech));

  EXPECT_THAT(signer->Sign(client_.get(), digest_info, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                             HasSubstr("algorithm NID mismatch")),
                    StatusRvIs(CKR_DATA_INVALID)));
}

TEST_F(RsaPkcs1Test, SignDigestLengthInvalid) {
  uint8_t digest[31], sig[256];
  ASSERT_OK_AND_ASSIGN(std::vector<uint8_t> digest_info,
                       BuildRsaDigestInfo(NID_sha256, digest));

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       RsaPkcs1Signer::New(prv_, &mech));

  EXPECT_THAT(signer->Sign(client_.get(), digest_info, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_DATA_LEN_RANGE)));
}

TEST_F(RsaPkcs1Test, SignSignatureLengthInvalid) {
  uint8_t digest[32], sig[255];
  ASSERT_OK_AND_ASSIGN(std::vector<uint8_t> digest_info,
                       BuildRsaDigestInfo(NID_sha256, digest));

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       RsaPkcs1Signer::New(prv_, &mech));

  EXPECT_THAT(signer->Sign(client_.get(), digest_info, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInternal),
                    StatusRvIs(CKR_GENERAL_ERROR)));
}

TEST_F(RsaPkcs1Test, SignVerifySuccess) {
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
  uint8_t digest[32];
  SHA256(data.data(), data.size(), digest);

  ASSERT_OK_AND_ASSIGN(std::vector<uint8_t> digest_info,
                       BuildRsaDigestInfo(NID_sha256, digest));

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       RsaPkcs1Signer::New(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->Sign(client_.get(), digest_info, absl::MakeSpan(sig)));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       RsaPkcs1Verifier::New(pub_, &mech));
  EXPECT_OK(verifier->Verify(client_.get(), digest_info, sig));
}

TEST_F(RsaPkcs1Test, VerifyUnparseableDigestInfo) {
  uint8_t digest_info[48], sig[256];
  RAND_bytes(digest_info, sizeof(digest_info));

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       RsaPkcs1Verifier::New(pub_, &mech));

  EXPECT_THAT(verifier->Verify(client_.get(), digest_info, sig),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                             HasSubstr("error parsing DigestInfo")),
                    StatusRvIs(CKR_DATA_INVALID)));
}

TEST_F(RsaPkcs1Test, VerifyWrongDigestType) {
  uint8_t digest[48], sig[256];
  ASSERT_OK_AND_ASSIGN(std::vector<uint8_t> digest_info,
                       BuildRsaDigestInfo(NID_sha384, digest));

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       RsaPkcs1Verifier::New(pub_, &mech));

  EXPECT_THAT(verifier->Verify(client_.get(), digest_info, sig),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                             HasSubstr("algorithm NID mismatch")),
                    StatusRvIs(CKR_DATA_INVALID)));
}

TEST_F(RsaPkcs1Test, VerifyDigestLengthInvalid) {
  uint8_t digest[31], sig[256];
  ASSERT_OK_AND_ASSIGN(std::vector<uint8_t> digest_info,
                       BuildRsaDigestInfo(NID_sha256, digest));

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       RsaPkcs1Verifier::New(pub_, &mech));

  EXPECT_THAT(verifier->Verify(client_.get(), digest_info, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_DATA_LEN_RANGE)));
}

TEST_F(RsaPkcs1Test, VerifySignatureLengthInvalid) {
  uint8_t digest[32], sig[255];
  ASSERT_OK_AND_ASSIGN(std::vector<uint8_t> digest_info,
                       BuildRsaDigestInfo(NID_sha256, digest));

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       RsaPkcs1Verifier::New(pub_, &mech));

  EXPECT_THAT(verifier->Verify(client_.get(), digest_info, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_SIGNATURE_LEN_RANGE)));
}

TEST_F(RsaPkcs1Test, VerifyBadSignature) {
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
  uint8_t digest[32], sig[256];
  SHA256(data.data(), data.size(), digest);

  ASSERT_OK_AND_ASSIGN(std::vector<uint8_t> digest_info,
                       BuildRsaDigestInfo(NID_sha256, digest));

  CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       RsaPkcs1Verifier::New(pub_, &mech));
  EXPECT_THAT(verifier->Verify(client_.get(), digest_info, sig),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_SIGNATURE_INVALID)));
}

}  // namespace
}  // namespace kmsp11
