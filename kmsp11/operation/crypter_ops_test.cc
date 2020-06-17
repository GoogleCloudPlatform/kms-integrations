#include "kmsp11/operation/crypter_ops.h"

#include "gmock/gmock.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/object.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/runfiles.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/crypto_utils.h"

namespace kmsp11 {
namespace {

TEST(DecryptOpTest, ValidMechanismSuccess) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  CK_RSA_PKCS_OAEP_PARAMS params{
      CKM_SHA256,          // hashAlg
      CKG_MGF1_SHA256,     // mgf
      CKZ_DATA_SPECIFIED,  // source
      nullptr,             // pSourceData
      0,                   // ulSourceDataLen
  };

  CK_MECHANISM mechanism{
      CKM_RSA_PKCS_OAEP,  // mechanism
      &params,            // pParameter
      sizeof(params),     // ulParameterLen
  };

  EXPECT_OK(NewDecryptOp(key, &mechanism));
}

TEST(DecryptOpTest, InvalidMechanismFailure) {
  CK_MECHANISM mech = {CKM_AES_ECB};
  EXPECT_THAT(NewDecryptOp(nullptr, &mech), StatusRvIs(CKR_MECHANISM_INVALID));
}

TEST(EncryptOpTest, ValidMechanismSuccess) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.public_key);

  CK_RSA_PKCS_OAEP_PARAMS params{
      CKM_SHA256,          // hashAlg
      CKG_MGF1_SHA256,     // mgf
      CKZ_DATA_SPECIFIED,  // source
      nullptr,             // pSourceData
      0,                   // ulSourceDataLen
  };

  CK_MECHANISM mechanism{
      CKM_RSA_PKCS_OAEP,  // mechanism
      &params,            // pParameter
      sizeof(params),     // ulParameterLen
  };

  EXPECT_OK(NewEncryptOp(key, &mechanism));
}

TEST(EncryptOpTest, InvalidMechanismFailure) {
  CK_MECHANISM mech = {CKM_AES_ECB};
  EXPECT_THAT(NewEncryptOp(nullptr, &mech), StatusRvIs(CKR_MECHANISM_INVALID));
}

TEST(SignOpTest, ValidMechanismSuccess) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp, NewMockKeyPair(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                                 "ec_p256_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  CK_MECHANISM mechanism{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(NewSignOp(key, &mechanism));
}

TEST(SignOpTest, InvalidMechanismFailure) {
  CK_MECHANISM mech = {CKM_SHA_1_HMAC};
  EXPECT_THAT(NewSignOp(nullptr, &mech), StatusRvIs(CKR_MECHANISM_INVALID));
}

TEST(VerifyOpTest, ValidMechanismSuccess) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp, NewMockKeyPair(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                                 "ec_p256_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.public_key);

  CK_MECHANISM mechanism{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(NewVerifyOp(key, &mechanism));
}

TEST(VerifyOpTest, InvalidMechanismFailure) {
  CK_MECHANISM mech = {CKM_SHA_1_HMAC};
  EXPECT_THAT(NewVerifyOp(nullptr, &mech), StatusRvIs(CKR_MECHANISM_INVALID));
}

}  // namespace
}  // namespace kmsp11