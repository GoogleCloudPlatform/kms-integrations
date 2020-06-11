#include "kmsp11/operation/crypter_ops.h"

#include "gmock/gmock.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/object.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/runfiles.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/crypto_utils.h"

namespace kmsp11 {
namespace {

TEST(DecryptOpTest, ValidMechanismSuccess) {
  kms_v1::CryptoKeyVersion ckv;
  ckv.set_name(
      "projects/foo/locations/bar/keyRings/baz/cryptoKeys/qux/"
      "cryptoKeyVersions/1");
  ckv.set_algorithm(kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ckv.set_state(kms_v1::CryptoKeyVersion::ENABLED);

  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("rsa_2048_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub,
                       ParseX509PublicKeyPem(pub_pem));
  ASSERT_OK_AND_ASSIGN(KeyPair kp, Object::NewKeyPair(ckv, pub.get()));
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

}  // namespace
}  // namespace kmsp11