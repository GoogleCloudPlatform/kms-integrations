#include "kmsp11/util/crypto_utils.h"

#include "absl/random/random.h"
#include "absl/strings/escaping.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "gmock/gmock.h"
#include "kmsp11/test/runfiles.h"
#include "kmsp11/test/test_status_macros.h"
#include "openssl/asn1.h"
#include "openssl/bn.h"
#include "openssl/bytestring.h"
#include "openssl/ec_key.h"
#include "openssl/obj.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"

namespace kmsp11 {
namespace {

using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::IsNull;
using ::testing::Not;

TEST(Asn1TimeToAbslTest, Epoch) {
  absl::Time epoch = absl::UnixEpoch();
  bssl::UniquePtr<ASN1_TIME> asn1_time(
      ASN1_TIME_set(nullptr, absl::ToTimeT(epoch)));

  EXPECT_THAT(Asn1TimeToAbsl(asn1_time.get()), IsOkAndHolds(epoch));
}

TEST(Asn1TimeToAbslTest, Now) {
  absl::Time now = absl::Now();
  bssl::UniquePtr<ASN1_TIME> asn1_time(
      ASN1_TIME_set(nullptr, absl::ToTimeT(now)));

  absl::Time now_seconds = absl::FromUnixSeconds(absl::ToUnixSeconds(now));
  EXPECT_THAT(Asn1TimeToAbsl(asn1_time.get()), IsOkAndHolds(now_seconds));
}

TEST(EncryptRsaOaepTest, EncryptDecryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("rsa_2048_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));

  std::string plaintext_str = "here is a sample plaintext";
  absl::Span<const uint8_t> plaintext(
      reinterpret_cast<const uint8_t*>(plaintext_str.data()),
      plaintext_str.size());
  std::vector<uint8_t> ciphertext(2048 / 8);

  EXPECT_OK(EncryptRsaOaep(pub_key.get(), EVP_sha256(), plaintext,
                           absl::MakeSpan(ciphertext)));

  // Some custom code to decrypt and compare
  ASSERT_OK_AND_ASSIGN(std::string prv_pem,
                       LoadTestRunfile("rsa_2048_private.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> prv_key,
                       ParsePkcs8PrivateKeyPem(prv_pem));

  bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(prv_key.get(), nullptr));
  EXPECT_TRUE(ctx);
  EXPECT_TRUE(EVP_PKEY_decrypt_init(ctx.get()));
  EXPECT_TRUE(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING));
  EXPECT_TRUE(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()));
  EXPECT_TRUE(EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()));

  std::vector<uint8_t> recovered(2048 / 8);
  size_t out_len = recovered.size();
  EXPECT_TRUE(EVP_PKEY_decrypt(ctx.get(), recovered.data(), &out_len,
                               ciphertext.data(), ciphertext.size()));
  recovered.resize(out_len);
  EXPECT_EQ(plaintext, recovered);
}

TEST(EncryptRsaOaepTest, InvalidArgumentErrorNullKey) {
  std::vector<uint8_t> plaintext = {0x01};
  std::vector<uint8_t> ciphertext(2048 / 8);

  EXPECT_THAT(EncryptRsaOaep(nullptr, EVP_sha256(), plaintext,
                             absl::MakeSpan(ciphertext)),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("missing required argument: key")));
}

TEST(EncryptRsaOaepTest, InvalidArgumentErrorNullHash) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("rsa_2048_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));

  std::vector<uint8_t> plaintext = {0x01};
  std::vector<uint8_t> ciphertext(2048 / 8);

  EXPECT_THAT(EncryptRsaOaep(pub_key.get(), nullptr, plaintext,
                             absl::MakeSpan(ciphertext)),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("missing required argument: hash")));
}

TEST(EncryptRsaOaepTest, InvalidArgumentErrorIncorrectKeyType) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("ec_p256_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));

  std::vector<uint8_t> plaintext = {0x01};
  std::vector<uint8_t> ciphertext(2048 / 8);

  EXPECT_THAT(EncryptRsaOaep(pub_key.get(), EVP_sha256(), plaintext,
                             absl::MakeSpan(ciphertext)),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("unexpected key type")));
}

TEST(EncryptRsaOaepTest, InvalidArgumentErrorPlaintextTooLong) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("rsa_2048_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));

  std::vector<uint8_t> plaintext(257);
  std::vector<uint8_t> ciphertext(2048 / 8);

  EXPECT_THAT(EncryptRsaOaep(pub_key.get(), EVP_sha256(), plaintext,
                             absl::MakeSpan(ciphertext)),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST(EncryptRsaOaepTest, InvalidArgumentErrorCiphertextTooShort) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("rsa_2048_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));

  std::vector<uint8_t> plaintext = {0x01};
  std::vector<uint8_t> ciphertext(255);

  EXPECT_THAT(EncryptRsaOaep(pub_key.get(), EVP_sha256(), plaintext,
                             absl::MakeSpan(ciphertext)),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("unexpected ciphertext size")));
}

TEST(EncryptRsaOaepTest, InvalidArgumentErrorCiphertextTooLong) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("rsa_2048_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));

  std::vector<uint8_t> plaintext = {0x01};
  std::vector<uint8_t> ciphertext(257);

  EXPECT_THAT(EncryptRsaOaep(pub_key.get(), EVP_sha256(), plaintext,
                             absl::MakeSpan(ciphertext)),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("unexpected ciphertext size")));
}

TEST(MarshalEcParametersTest, CurveOidMarshaled) {
  // Generate a new P-384 key
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_secp384r1));
  EXPECT_TRUE(EC_KEY_generate_key(key.get()));

  // Serialize the EC parameters (group)
  ASSERT_OK_AND_ASSIGN(std::string oid_der, MarshalEcParametersDer(key.get()));

  // Deserialize the EC parameters and read the curve's OID
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(oid_der.data()),
           oid_der.size());
  CBS oid;
  EXPECT_TRUE(CBS_get_asn1(&cbs, &oid, CBS_ASN1_OBJECT));

  // Ensure the retrieved OID matches the expected
  EXPECT_EQ(OBJ_cbs2nid(&oid), OBJ_txt2nid("1.3.132.0.34"));
}

TEST(MarshalEcPointTest, PointMarshaled) {
  // Generate a new P-256 key
  bssl::UniquePtr<EC_GROUP> group(
      EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new());
  EXPECT_TRUE(EC_KEY_set_group(key.get(), group.get()));
  EXPECT_TRUE(EC_KEY_generate_key(key.get()));

  // Serialize the public key point
  ASSERT_OK_AND_ASSIGN(std::string point_der, MarshalEcPointDer(key.get()));

  // Deserialize the public key point
  bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  EXPECT_TRUE(
      EC_POINT_oct2point(group.get(), point.get(),
                         reinterpret_cast<const uint8_t*>(point_der.data()),
                         point_der.size(), bn_ctx.get()));

  // Ensure the deserialized point matches the original
  EXPECT_EQ(EC_POINT_cmp(group.get(), EC_KEY_get0_public_key(key.get()),
                         point.get(), bn_ctx.get()),
            0);
}

TEST(MarshalX509CertificateTest, MarshalPemToDer) {
  ASSERT_OK_AND_ASSIGN(std::string pem, LoadTestRunfile("ec_p256_cert.pem"));
  ASSERT_OK_AND_ASSIGN(std::string der, LoadTestRunfile("ec_p256_cert.der"));

  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  EXPECT_EQ(BIO_write(bio.get(), pem.data(), pem.size()), pem.size());
  bssl::UniquePtr<X509> cert(
      PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));

  EXPECT_THAT(MarshalX509CertificateDer(cert.get()), IsOkAndHolds(der));
}

TEST(ParseAndMarshalPublicKeyTest, EcKey) {
  // Parse the public key in PEM format.
  ASSERT_OK_AND_ASSIGN(std::string pem, LoadTestRunfile("ec_p256_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                       ParseX509PublicKeyPem(pem));

  // Marshal the public key in DER format.
  ASSERT_OK_AND_ASSIGN(std::string got_der,
                       MarshalX509PublicKeyDer(parsed_key.get()));

  // Ensure the marshaled key matches the expected.
  ASSERT_OK_AND_ASSIGN(std::string want_der,
                       LoadTestRunfile("ec_p256_public.der"));
  EXPECT_EQ(got_der, want_der);
}

TEST(ParseAndMarshalPublicKeyTest, RsaKey) {
  // Parse the public key in PEM format.
  ASSERT_OK_AND_ASSIGN(std::string pem, LoadTestRunfile("rsa_2048_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                       ParseX509PublicKeyPem(pem));

  // Marshal the public key in DER format.
  ASSERT_OK_AND_ASSIGN(std::string got_der,
                       MarshalX509PublicKeyDer(parsed_key.get()));

  // Ensure the marshaled key matches the expected.
  ASSERT_OK_AND_ASSIGN(std::string want_der,
                       LoadTestRunfile("rsa_2048_public.der"));
  EXPECT_EQ(got_der, want_der);
}

TEST(ParsePrivateKeyTest, EcKey) {
  // Parse the private key in PEM format.
  ASSERT_OK_AND_ASSIGN(std::string pem, LoadTestRunfile("ec_p256_private.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> key,
                       ParsePkcs8PrivateKeyPem(pem));

  const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(key.get());
  EXPECT_TRUE(EC_KEY_get0_private_key(ec_key));
  EXPECT_TRUE(EC_KEY_check_key(ec_key));
  EXPECT_TRUE(EC_KEY_check_fips(ec_key));
}

TEST(ParsePrivateKeyTest, RsaKey) {
  // Parse the private key in PEM format.
  ASSERT_OK_AND_ASSIGN(std::string pem,
                       LoadTestRunfile("rsa_2048_private.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> key,
                       ParsePkcs8PrivateKeyPem(pem));

  RSA* rsa = EVP_PKEY_get0_RSA(key.get());
  EXPECT_TRUE(RSA_get0_e(rsa));
  EXPECT_TRUE(RSA_check_key(rsa));
  EXPECT_TRUE(RSA_check_fips(rsa));
}

TEST(ParsePublicKeyTest, EcKey) {
  // Parse the public key in DER format.
  ASSERT_OK_AND_ASSIGN(std::string der, LoadTestRunfile("ec_p256_public.der"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> key,
                       ParseX509PublicKeyDer(der));

  const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(key.get());
  EXPECT_TRUE(EC_KEY_get0_public_key(ec_key));
  EXPECT_TRUE(EC_KEY_check_key(ec_key));
  EXPECT_TRUE(EC_KEY_check_fips(ec_key));
}

TEST(ParsePublicKeyTest, RsaKey) {
  // Parse the public key in DER format.
  ASSERT_OK_AND_ASSIGN(std::string der, LoadTestRunfile("rsa_2048_public.der"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> key,
                       ParseX509PublicKeyDer(der));

  RSA* rsa = EVP_PKEY_get0_RSA(key.get());
  EXPECT_TRUE(RSA_get0_e(rsa));
  EXPECT_TRUE(RSA_check_key(rsa));
  EXPECT_TRUE(RSA_check_fips(rsa));
}

TEST(RandBytesTest, SmokeTest) {
  std::string rand = RandBytes(8);
  EXPECT_EQ(rand.size(), 8);
  EXPECT_NE(rand, std::string("\x00", 8));
}

TEST(SslErrorToStringTest, ErrorEmitted) {
  bssl::UniquePtr<EC_KEY> ec_key(EC_KEY_new_by_curve_name(0));
  EXPECT_THAT(ec_key, IsNull());
  EXPECT_THAT(SslErrorToString(), HasSubstr("UNKNOWN_GROUP"));
}

TEST(SslErrorToStringTest, EmptyStringOnNoError) {
  bssl::UniquePtr<EC_KEY> ec_key(
      EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  EXPECT_THAT(ec_key, Not(IsNull()));
  EXPECT_THAT(SslErrorToString(), IsEmpty());
}

TEST(BoringBitGeneratorTest, SmokeTest) {
  BoringBitGenerator bbg;
  uint16_t generated = absl::Uniform<uint16_t>(bbg, 12, 24);
  EXPECT_GE(generated, 12);
  EXPECT_LT(generated, 24);
}

}  // namespace
}  // namespace kmsp11