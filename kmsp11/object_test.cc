#include "kmsp11/object.h"

#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/crypto_utils.h"
#include "openssl/rsa.h"

namespace kmsp11 {
namespace {

using ::testing::Each;
using ::testing::ElementsAre;
using ::testing::Field;

namespace kms_v1 = ::google::cloud::kms::v1;

kms_v1::CryptoKeyVersion NewTestCkv() {
  kms_v1::CryptoKeyVersion v;
  v.set_name(
      "projects/foo/locations/global/keyRings/bar/cryptoKeys/baz/"
      "cryptoKeyVersions/1");
  v.set_algorithm(
      kms_v1::CryptoKeyVersion_CryptoKeyVersionAlgorithm_EC_SIGN_P256_SHA256);
  return v;
}

StatusOr<bssl::UniquePtr<EVP_PKEY>> GetTestP256Key() {
  static const char* key_pem = R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7vZa2EcY4GKQXWUObY7EXWEkGZZt
8QljjI2sA1T1t2p+Vu/G4g6o1zfMCpDNvJFxA+1JwNqdiBUqox9Ie0CNOg==
-----END PUBLIC KEY-----)";
  return ParseX509PublicKeyPem(key_pem);
}

StatusOr<bssl::UniquePtr<EVP_PKEY>> GetTestRsa2048Key() {
  static const char* key_pem = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmqD9FEz81Yo/OuwbQqmH
dY5JdTZNSkAAqIn08BqS6t6LRHQ2gUXKy2LVgMXCgwt/g9pCzB4+x1Vx8/WPWzmq
f2x5d/XT28ZEVbFtUpa5XDhGasP+rgTMj6cAaQk31zm4GE7zCil3ohgNAMzwHpg+
J+ckkYoBQ2FT01neTMxGHFidNQGHEONQ5tDOFa/hU4RFTN7QB6tQ4k2J1BEvT25Z
7RTmo0stzQi3032En7EE3POlPC1Mj8itRuYMf8nNtaRALKIqYpEAUTSCnme4EIl2
bMvH8DIgLW5muXaJI9ys5tsT19pIkxaN2x/Icc19QS6SMaTF/o/MvLkdwWbj13uA
yQIDAQAB
-----END PUBLIC KEY-----)";
  return ParseX509PublicKeyPem(key_pem);
}

TEST(NewKeyPairTest, KmsKeyNameMatches) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));

  EXPECT_EQ(key_pair.public_key.kms_key_name(), ckv.name());
  EXPECT_EQ(key_pair.private_key.kms_key_name(), ckv.name());
}

TEST(NewKeyPairTest, ObjectClassMatches) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));

  EXPECT_EQ(key_pair.public_key.object_class(), CKO_PUBLIC_KEY);
  EXPECT_EQ(key_pair.private_key.object_class(), CKO_PRIVATE_KEY);
}

TEST(NewKeyPairTest, AlgorithmMatches) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));

  std::vector<AlgorithmDetails> algs = {key_pair.public_key.algorithm(),
                                        key_pair.private_key.algorithm()};
  EXPECT_THAT(
      algs,
      Each(AllOf(
          Field("algorithm", &AlgorithmDetails::algorithm, ckv.algorithm()),
          Field("key_bit_length", &AlgorithmDetails::key_bit_length, 256),
          Field("key_type", &AlgorithmDetails::key_type, CKK_EC))));
}

TEST(NewKeyPairTest, LabelMatches) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));

  EXPECT_THAT(key_pair.public_key.attributes().Value(CKA_LABEL),
              IsOkAndHolds("baz"));
  EXPECT_THAT(key_pair.private_key.attributes().Value(CKA_LABEL),
              IsOkAndHolds("baz"));
}

TEST(NewKeyPairTest, PublicKeyAttributes) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));
  const AttributeMap& attrs = key_pair.public_key.attributes();

  // check a handful of the attributes to make sure they're consistent
  EXPECT_THAT(attrs.Value(CKA_TOKEN), IsOkAndHolds(MarshalBool(true)));
  EXPECT_THAT(attrs.Value(CKA_PRIVATE), IsOkAndHolds(MarshalBool(false)));
  EXPECT_THAT(attrs.Value(CKA_DERIVE), IsOkAndHolds(MarshalBool(false)));
  EXPECT_THAT(attrs.Value(CKA_VERIFY), IsOkAndHolds(MarshalBool(true)));
  EXPECT_THAT(attrs.Value(CKA_ENCRYPT), IsOkAndHolds(MarshalBool(false)));

  // check a couple of attributes that shouldn't be set
  EXPECT_THAT(attrs.Value(CKA_SIGN), StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));
  EXPECT_THAT(attrs.Value(CKA_ISSUER), StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));
}

TEST(NewKeyPairTest, PrivateKeyAttributes) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));
  const AttributeMap& attrs = key_pair.private_key.attributes();

  // check a handful of the attributes to make sure they're consistent
  EXPECT_THAT(attrs.Value(CKA_SUBJECT), IsOkAndHolds(""));
  EXPECT_THAT(attrs.Value(CKA_MODIFIABLE), IsOkAndHolds(MarshalBool(false)));
  EXPECT_THAT(attrs.Value(CKA_DERIVE), IsOkAndHolds(MarshalBool(false)));
  EXPECT_THAT(attrs.Value(CKA_SIGN), IsOkAndHolds(MarshalBool(true)));
  EXPECT_THAT(attrs.Value(CKA_DECRYPT), IsOkAndHolds(MarshalBool(false)));

  // check a couple of attributes that shouldn't be set
  EXPECT_THAT(attrs.Value(CKA_VERIFY), StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));
  EXPECT_THAT(attrs.Value(CKA_COLOR), StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));
}

TEST(NewKeyPairTest, EcKeyAttributes) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());
  const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pub.get());

  ASSERT_OK_AND_ASSIGN(std::string params, MarshalEcParametersDer(ec_key));
  ASSERT_OK_AND_ASSIGN(std::string point, MarshalEcPointDer(ec_key));

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));
  const AttributeMap& pub_attrs = key_pair.public_key.attributes();
  const AttributeMap& prv_attrs = key_pair.private_key.attributes();

  EXPECT_THAT(pub_attrs.Value(CKA_EC_PARAMS), IsOkAndHolds(params));
  EXPECT_THAT(pub_attrs.Value(CKA_EC_POINT), IsOkAndHolds(point));
  EXPECT_THAT(pub_attrs.Value(CKA_VALUE),
              StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));

  EXPECT_THAT(prv_attrs.Value(CKA_EC_PARAMS), IsOkAndHolds(params));
  EXPECT_THAT(prv_attrs.Value(CKA_EC_POINT), IsOkAndHolds(point));
  EXPECT_THAT(prv_attrs.Value(CKA_VALUE), StatusRvIs(CKR_ATTRIBUTE_SENSITIVE));
}

TEST(NewKeyPairTest, RsaKeyAttributes) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ckv.set_algorithm(
      kms_v1::
          CryptoKeyVersion_CryptoKeyVersionAlgorithm_RSA_SIGN_PKCS1_2048_SHA256);

  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestRsa2048Key());
  const RSA* rsa_key = EVP_PKEY_get0_RSA(pub.get());

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));
  const AttributeMap& pub_attrs = key_pair.public_key.attributes();
  const AttributeMap& prv_attrs = key_pair.private_key.attributes();

  EXPECT_THAT(pub_attrs.Value(CKA_MODULUS_BITS),
              IsOkAndHolds(MarshalULong(2048)));
  EXPECT_THAT(pub_attrs.Value(CKA_MODULUS),
              IsOkAndHolds(MarshalBigNum(RSA_get0_n(rsa_key))));
  EXPECT_THAT(pub_attrs.Value(CKA_PUBLIC_EXPONENT),
              IsOkAndHolds(MarshalBigNum(RSA_get0_e(rsa_key))));
  EXPECT_THAT(pub_attrs.Value(CKA_PRIVATE_EXPONENT),
              StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));

  EXPECT_THAT(prv_attrs.Value(CKA_MODULUS_BITS),
              IsOkAndHolds(MarshalULong(2048)));
  EXPECT_THAT(prv_attrs.Value(CKA_PUBLIC_EXPONENT),
              IsOkAndHolds(MarshalBigNum(RSA_get0_e(rsa_key))));
  EXPECT_THAT(prv_attrs.Value(CKA_PRIVATE_EXPONENT),
              StatusRvIs(CKR_ATTRIBUTE_SENSITIVE));
  EXPECT_THAT(prv_attrs.Value(CKA_PRIME_2),
              StatusRvIs(CKR_ATTRIBUTE_SENSITIVE));
}

}  // namespace
}  // namespace kmsp11