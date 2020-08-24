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
#include "openssl/sha.h"

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

TEST(EcdsaSigAsn1ToP1363Test, ValidSignature) {
  bssl::UniquePtr<EC_GROUP> g(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));

  std::string asn1_sig = absl::HexStringToBytes(
      "304502203B0C7CD5208944E1F7DDDAA304B4129A33FDD9449EED83EB14A1F2A780CB1436"
      "022100BF049416636F7981A2C3DD8B68E5850590E6C536C3E81A55F259C4D9988DD97E");

  std::string expected_p1363_sig = absl::HexStringToBytes(
      "3B0C7CD5208944E1F7DDDAA304B4129A33FDD9449EED83EB14A1F2A780CB1436"    // r
      "BF049416636F7981A2C3DD8B68E5850590E6C536C3E81A55F259C4D9988DD97E");  // s
  absl::Span<const uint8_t> p1363_bytes = absl::MakeConstSpan(
      reinterpret_cast<const uint8_t*>(expected_p1363_sig.data()),
      expected_p1363_sig.size());

  EXPECT_THAT(EcdsaSigAsn1ToP1363(asn1_sig, g.get()),
              IsOkAndHolds(p1363_bytes));
}

TEST(EcdsaSigAsn1ToP1363Test, BadData) {
  bssl::UniquePtr<EC_GROUP> g(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  EXPECT_THAT(EcdsaSigAsn1ToP1363("abcde", g.get()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSigAsn1ToP1363Test, GroupTooSmallForSignature) {
  bssl::UniquePtr<EC_GROUP> g(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  std::string p384_sig = absl::HexStringToBytes(
      "3065023012b30abef6b5476fe6b612ae557c0425661e26b44b1bfe19daf2ca28e3113083"
      "ba8e4ae4cc45a0320abd3394f1c548d7023100e7bf25603e2d07076ff30b7a2abec473da"
      "8b11c572b35fc631991d5de62ddca7525aaba89325dfd04fecc47bff426f82");
  EXPECT_THAT(EcdsaSigAsn1ToP1363(p384_sig, g.get()),
              StatusIs(absl::StatusCode::kOutOfRange));
}

TEST(EcdsaSigLengthTest, P256Length) {
  bssl::UniquePtr<EC_GROUP> g(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  EXPECT_EQ(EcdsaSigLengthP1363(g.get()), 64);
}

TEST(EcdsaSigLengthTest, P521Length) {
  bssl::UniquePtr<EC_GROUP> g(EC_GROUP_new_by_curve_name(NID_secp521r1));
  EXPECT_EQ(EcdsaSigLengthP1363(g.get()), 132);
}

TEST(EcdsaVerifyP1363Test, ValidSignature) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("ec_p256_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));
  EC_KEY* ec_pub = EVP_PKEY_get0_EC_KEY(pub_key.get());
  EXPECT_TRUE(ec_pub);

  std::string data = "This is a message to authenticate\n";
  uint8_t data_hash[32];
  SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), data_hash);

  std::string valid_sig = absl::HexStringToBytes(
      "3B0C7CD5208944E1F7DDDAA304B4129A33FDD9449EED83EB14A1F2A780CB1436"    // r
      "BF049416636F7981A2C3DD8B68E5850590E6C536C3E81A55F259C4D9988DD97E");  // s
  absl::Span<const uint8_t> valid_sig_bytes = absl::MakeConstSpan(
      reinterpret_cast<const uint8_t*>(valid_sig.data()), valid_sig.size());

  EXPECT_OK(EcdsaVerifyP1363(ec_pub, EVP_sha256(), data_hash, valid_sig_bytes));
}

TEST(EcdsaVerifyP1363Test, InvalidSignatureDigestLength) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("ec_p256_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));
  EC_KEY* ec_pub = EVP_PKEY_get0_EC_KEY(pub_key.get());
  EXPECT_TRUE(ec_pub);

  uint8_t data_hash[31], sig_bytes[64];
  EXPECT_THAT(EcdsaVerifyP1363(ec_pub, EVP_sha256(), data_hash, sig_bytes),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST(EcdsaVerifyP1363Test, InvalidSignatureBitFlip) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("ec_p256_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));
  EC_KEY* ec_pub = EVP_PKEY_get0_EC_KEY(pub_key.get());
  EXPECT_TRUE(ec_pub);

  std::string data = "This is a message to authenticate\n";
  uint8_t data_hash[32];
  SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), data_hash);

  std::string last_bit_flipped = absl::HexStringToBytes(
      "3B0C7CD5208944E1F7DDDAA304B4129A33FDD9449EED83EB14A1F2A780CB1436"    // r
      "BF049416636F7981A2C3DD8B68E5850590E6C536C3E81A55F259C4D9988DD97F");  // s
  absl::Span<const uint8_t> sig_bytes = absl::MakeConstSpan(
      reinterpret_cast<const uint8_t*>(last_bit_flipped.data()),
      last_bit_flipped.size());

  EXPECT_THAT(EcdsaVerifyP1363(ec_pub, EVP_sha256(), data_hash, sig_bytes),
              StatusRvIs(CKR_SIGNATURE_INVALID));
}

TEST(EcdsaVerifyP1363Test, InvalidSignatureOddLength) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("ec_p256_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));
  EC_KEY* ec_pub = EVP_PKEY_get0_EC_KEY(pub_key.get());
  EXPECT_TRUE(ec_pub);

  std::string data = "This is a message to authenticate\n";
  uint8_t data_hash[32];
  SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), data_hash);

  std::string last_byte_omitted = absl::HexStringToBytes(
      "3B0C7CD5208944E1F7DDDAA304B4129A33FDD9449EED83EB14A1F2A780CB1436"
      "BF049416636F7981A2C3DD8B68E5850590E6C536C3E81A55F259C4D9988DD9");
  absl::Span<const uint8_t> sig_bytes = absl::MakeConstSpan(
      reinterpret_cast<const uint8_t*>(last_byte_omitted.data()),
      last_byte_omitted.size());

  EXPECT_THAT(EcdsaVerifyP1363(ec_pub, EVP_sha256(), data_hash, sig_bytes),
              StatusRvIs(CKR_SIGNATURE_LEN_RANGE));
}

TEST(EcdsaVerifyP1363Test, InvalidSignatureTooLong) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("ec_p256_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));
  EC_KEY* ec_pub = EVP_PKEY_get0_EC_KEY(pub_key.get());
  EXPECT_TRUE(ec_pub);

  std::string data = "This is a message to authenticate\n";
  uint8_t data_hash[32];
  SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), data_hash);

  std::string extra_byte = absl::HexStringToBytes(
      "3B0C7CD5208944E1F7DDDAA304B4129A33FDD9449EED83EB14A1F2A780CB1436"
      "BF049416636F7981A2C3DD8B68E5850590E6C536C3E81A55F259C4D9988DD97EFF");
  absl::Span<const uint8_t> sig_bytes = absl::MakeConstSpan(
      reinterpret_cast<const uint8_t*>(extra_byte.data()), extra_byte.size());

  EXPECT_THAT(EcdsaVerifyP1363(ec_pub, EVP_sha256(), data_hash, sig_bytes),
              StatusRvIs(CKR_SIGNATURE_LEN_RANGE));
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

TEST(RandomHandleTest, SmokeTest) {
  CK_ULONG generated = RandomHandle();
  EXPECT_GT(generated, 0);
  EXPECT_LE(generated, std::numeric_limits<CK_ULONG>::max());
}

TEST(RsaVerifyPkcs1Test, ValidSignature) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("rsa_2048_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));
  RSA* rsa_pub = EVP_PKEY_get0_RSA(pub_key.get());
  EXPECT_TRUE(rsa_pub);

  std::string data = "This is a message to authenticate\n";
  uint8_t data_hash[32];
  SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), data_hash);

  std::string valid_sig;
  EXPECT_TRUE(absl::Base64Unescape(R"(
    APLPMR1LqgEwDqT6fmeZtZvfFePOLEnzivPS05HMhxakWJLXLJUvmRmwk0QuNzPNREDLuU7y9VV7
    h/dVRuWrhPiSaswPFhhmOfiymSpK7F6Q12TucdtL/TxVdBBDL02sBOrO/d9eye8k0Ija1amkn17R
    aw5rqeSjuHgHIni8K7boGDBhKVoMLxLt3XQfMKcysAHbNAWigjuVop9Clvn22USvVvFW/08108j0
    VH8B1zK9JWqPnVJcaKmXP4lohlXKYdHe2sfE9YUhObZfw4t6zQHRowF3C05TBcQjPLbJ353vk/VL
    P7a+mRjHlI2l5QJ6lfC1VOzbsPgAytoKxkGMvA==)",
                                   &valid_sig));
  absl::Span<const uint8_t> valid_sig_bytes = absl::MakeConstSpan(
      reinterpret_cast<const uint8_t*>(valid_sig.data()), valid_sig.size());

  EXPECT_OK(RsaVerifyPkcs1(rsa_pub, EVP_sha256(), data_hash, valid_sig_bytes));
}

TEST(RsaVerifyPkcs1Test, InvalidSignatureDigestLength) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("rsa_2048_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));
  RSA* rsa_pub = EVP_PKEY_get0_RSA(pub_key.get());
  EXPECT_TRUE(rsa_pub);

  uint8_t data_hash[31], sig_bytes[256];
  EXPECT_THAT(RsaVerifyPkcs1(rsa_pub, EVP_sha256(), data_hash, sig_bytes),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST(RsaVerifyPkcs1Test, InvalidSignatureBitFlip) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("rsa_2048_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));
  RSA* rsa_pub = EVP_PKEY_get0_RSA(pub_key.get());
  EXPECT_TRUE(rsa_pub);

  std::string data = "This is a message to authenticate\n";
  uint8_t data_hash[32];
  SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), data_hash);

  std::string sig;
  EXPECT_TRUE(absl::Base64Unescape(R"(
    APLPMR1LqgEwDqT6fmeZtZvfFePOLEnzivPS05HMhxakWJLXLJUvmRmwk0QuNzPNREDLuU7y9VV7
    h/dVRuWrhPiSaswPFhhmOfiymSpK7F6Q12TucdtL/TxVdBBDL02sBOrO/d9eye8k0Ija1amkn17R
    aw5rqeSjuHgHIni8K7boGDBhKVoMLxLt3XQfMKcysAHbNAWigjuVop9Clvn22USvVvFW/08108j0
    VH8B1zK9JWqPnVJcaKmXP4lohlXKYdHe2sfE9YUhObZfw4t6zQHRowF3C05TBcQjPLbJ353vk/VL
    P7a+mRjHlI2l5QJ6lfC1VOzbsPgAytoKxkGMvA==)",
                                   &sig));
  sig[0] ^= 0x01;  // flip a bit
  absl::Span<const uint8_t> sig_bytes = absl::MakeConstSpan(
      reinterpret_cast<const uint8_t*>(sig.data()), sig.size());

  EXPECT_THAT(RsaVerifyPkcs1(rsa_pub, EVP_sha256(), data_hash, sig_bytes),
              StatusRvIs(CKR_SIGNATURE_INVALID));
}

TEST(RsaVerifyPkcs1Test, InvalidSignatureSigLength) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("rsa_2048_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));
  RSA* rsa_pub = EVP_PKEY_get0_RSA(pub_key.get());
  EXPECT_TRUE(rsa_pub);

  uint8_t data_hash[32], sig_bytes[255];
  EXPECT_THAT(RsaVerifyPkcs1(rsa_pub, EVP_sha256(), data_hash, sig_bytes),
              StatusRvIs(CKR_SIGNATURE_LEN_RANGE));
}

TEST(RsaVerifyPssTest, ValidSignature) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("rsa_2048_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));
  RSA* rsa_pub = EVP_PKEY_get0_RSA(pub_key.get());
  EXPECT_TRUE(rsa_pub);

  std::string data = "This is a message to authenticate\n";
  uint8_t data_hash[32];
  SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), data_hash);

  std::string valid_sig;
  EXPECT_TRUE(absl::Base64Unescape(R"(
    KUgmGc4UVV9M42CGPydJaIV/u7AveP3xnJUSLQK+ULvRcdnZ7shGSSMqxnlF27EMtnoNDtHWCwOQ
    kGwWZ4Y+z8fLhkcFPajV9zzrBG8+h9F10TjOUG6oxJkl64PGiEzodPcoPG+mLsbUeBya/nzgv/6L
    j7PtSC6NmDQnUhpisWjWR3MO4NbF8Mq/jC0CVC91T2mVWcZ+kRFMzTc2hMjy1V+lmT84u4vrzkUH
    jFnNFHvIj5aXGChOwiXMw/nOzVtFX4DL/pdtWZ1letj1fzg6/UksXlh1XA9s2T3QideSDuhrC2pV
    +0m/CE5V3KA40Uec3EOH9EDkc3NIPKH8PIMSFw==)",
                                   &valid_sig));
  absl::Span<const uint8_t> valid_sig_bytes = absl::MakeConstSpan(
      reinterpret_cast<const uint8_t*>(valid_sig.data()), valid_sig.size());

  EXPECT_OK(RsaVerifyPss(rsa_pub, EVP_sha256(), data_hash, valid_sig_bytes));
}

TEST(RsaVerifyPssTest, InvalidSignatureDigestLength) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("rsa_2048_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));
  RSA* rsa_pub = EVP_PKEY_get0_RSA(pub_key.get());
  EXPECT_TRUE(rsa_pub);

  uint8_t data_hash[31], sig_bytes[256];
  EXPECT_THAT(RsaVerifyPss(rsa_pub, EVP_sha256(), data_hash, sig_bytes),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST(RsaVerifyPssTest, InvalidSignatureBitFlip) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("rsa_2048_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));
  RSA* rsa_pub = EVP_PKEY_get0_RSA(pub_key.get());
  EXPECT_TRUE(rsa_pub);

  std::string data = "This is a message to authenticate\n";
  uint8_t data_hash[32];
  SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), data_hash);

  std::string sig;
  EXPECT_TRUE(absl::Base64Unescape(R"(
    KUgmGc4UVV9M42CGPydJaIV/u7AveP3xnJUSLQK+ULvRcdnZ7shGSSMqxnlF27EMtnoNDtHWCwOQ
    kGwWZ4Y+z8fLhkcFPajV9zzrBG8+h9F10TjOUG6oxJkl64PGiEzodPcoPG+mLsbUeBya/nzgv/6L
    j7PtSC6NmDQnUhpisWjWR3MO4NbF8Mq/jC0CVC91T2mVWcZ+kRFMzTc2hMjy1V+lmT84u4vrzkUH
    jFnNFHvIj5aXGChOwiXMw/nOzVtFX4DL/pdtWZ1letj1fzg6/UksXlh1XA9s2T3QideSDuhrC2pV
    +0m/CE5V3KA40Uec3EOH9EDkc3NIPKH8PIMSFw==)",
                                   &sig));
  sig[0] ^= 0x01;  // flip a bit
  absl::Span<const uint8_t> sig_bytes = absl::MakeConstSpan(
      reinterpret_cast<const uint8_t*>(sig.data()), sig.size());

  EXPECT_THAT(RsaVerifyPss(rsa_pub, EVP_sha256(), data_hash, sig_bytes),
              StatusRvIs(CKR_SIGNATURE_INVALID));
}

TEST(RsaVerifyPssTest, InvalidSignatureSigLength) {
  ASSERT_OK_AND_ASSIGN(std::string pub_pem,
                       LoadTestRunfile("rsa_2048_public.pem"));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_key,
                       ParseX509PublicKeyPem(pub_pem));
  RSA* rsa_pub = EVP_PKEY_get0_RSA(pub_key.get());
  EXPECT_TRUE(rsa_pub);

  uint8_t data_hash[32], sig_bytes[255];
  EXPECT_THAT(RsaVerifyPss(rsa_pub, EVP_sha256(), data_hash, sig_bytes),
              StatusRvIs(CKR_SIGNATURE_LEN_RANGE));
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

}  // namespace
}  // namespace kmsp11