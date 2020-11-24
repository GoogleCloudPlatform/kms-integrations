#include "kmsp11/util/kms_client.h"

#include "absl/time/time.h"
#include "gmock/gmock.h"
#include "kmsp11/test/fakekms/cpp/fakekms.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/crypto_utils.h"
#include "openssl/ec_key.h"
#include "openssl/sha.h"

namespace kmsp11 {
namespace {

std::unique_ptr<KmsClient> NewClient(
    absl::string_view listen_addr,
    absl::Duration rpc_timeout = absl::Milliseconds(500)) {
  return absl::make_unique<KmsClient>(
      listen_addr, grpc::InsecureChannelCredentials(), rpc_timeout);
}

TEST(KmsClientTest, ListCryptoKeysSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeKms> fake, FakeKms::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck1;
  ck1.set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);
  ck1 = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck1", ck1, true);

  kms_v1::CryptoKey ck2;
  ck2.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
  ck2.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ck2 = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck2", ck2, true);

  kms_v1::ListCryptoKeysRequest list_req;
  list_req.set_parent(kr.name());
  CryptoKeysRange range = client->ListCryptoKeys(list_req);

  CryptoKeysRange::iterator it = range.begin();
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKey rck1, *it);
  EXPECT_THAT(rck1, EqualsProto(ck1));

  it++;
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKey rck2, *it);
  EXPECT_THAT(rck2, EqualsProto(ck2));

  it++;
  EXPECT_EQ(it, range.end());
}

TEST(KmsClientTest, ListCryptoKeysFailureInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeKms> fake, FakeKms::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::ListCryptoKeysRequest list_req;
  list_req.set_parent("foo");
  CryptoKeysRange range = client->ListCryptoKeys(list_req);

  CryptoKeysRange::iterator it = range.begin();
  EXPECT_THAT(*it, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest, ListCryptoKeyVersionsSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeKms> fake, FakeKms::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv1;
  ckv1 = CreateCryptoKeyVersionOrDie(client->kms_stub(), ck.name(), ckv1);
  ckv1 = WaitForEnablement(client->kms_stub(), ckv1);

  kms_v1::CryptoKeyVersion ckv2;
  ckv2 = CreateCryptoKeyVersionOrDie(client->kms_stub(), ck.name(), ckv2);
  ckv2 = WaitForEnablement(client->kms_stub(), ckv2);

  kms_v1::ListCryptoKeyVersionsRequest list_req;
  list_req.set_parent(ck.name());
  CryptoKeyVersionsRange range = client->ListCryptoKeyVersions(list_req);

  CryptoKeyVersionsRange::iterator it = range.begin();
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKeyVersion rckv1, *it);
  EXPECT_THAT(rckv1, EqualsProto(ckv1));

  it++;
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKeyVersion rckv2, *it);
  EXPECT_THAT(rckv2, EqualsProto(ckv2));

  it++;
  EXPECT_EQ(it, range.end());
}

TEST(KmsClientTest, ListCryptoKeyVersionsFailureInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeKms> fake, FakeKms::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::ListCryptoKeyVersionsRequest list_req;
  list_req.set_parent("foo");
  CryptoKeyVersionsRange range = client->ListCryptoKeyVersions(list_req);

  CryptoKeyVersionsRange::iterator it = range.begin();
  EXPECT_THAT(*it, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest, GetPublicKeySuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeKms> fake, FakeKms::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(client->kms_stub(), ck.name(), ckv);
  ckv = WaitForEnablement(client->kms_stub(), ckv);

  kms_v1::GetPublicKeyRequest pub_req;
  pub_req.set_name(ckv.name());
  ASSERT_OK_AND_ASSIGN(kms_v1::PublicKey pk, client->GetPublicKey(pub_req));

  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub,
                       ParseX509PublicKeyPem(pk.pem()));
  EXPECT_TRUE(EVP_PKEY_get0_EC_KEY(pub.get()));
}

TEST(KmsClientTest, GetPublicKeyFailureInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeKms> fake, FakeKms::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::GetPublicKeyRequest pub_req;
  pub_req.set_name("foo");
  EXPECT_THAT(client->GetPublicKey(pub_req),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest, AsymmetricDecryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeKms> fake, FakeKms::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(client->kms_stub(), ck.name(), ckv);
  ckv = WaitForEnablement(client->kms_stub(), ckv);

  kms_v1::GetPublicKeyRequest pub_req;
  pub_req.set_name(ckv.name());
  ASSERT_OK_AND_ASSIGN(kms_v1::PublicKey pk, client->GetPublicKey(pub_req));

  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub,
                       ParseX509PublicKeyPem(pk.pem()));

  std::string plaintext_str = "Here is a sample plaintext";
  absl::Span<const uint8_t> plaintext(
      reinterpret_cast<const uint8_t*>(plaintext_str.data()),
      plaintext_str.size());

  uint8_t ct_data[256];
  absl::Span<uint8_t> ciphertext = absl::MakeSpan(ct_data);

  EXPECT_OK(EncryptRsaOaep(pub.get(), EVP_sha256(), plaintext, ciphertext));

  kms_v1::AsymmetricDecryptRequest decrypt_req;
  decrypt_req.set_name(ckv.name());
  decrypt_req.set_ciphertext(ciphertext.data(), ciphertext.size());

  ASSERT_OK_AND_ASSIGN(kms_v1::AsymmetricDecryptResponse decrypt_resp,
                       client->AsymmetricDecrypt(decrypt_req));
  EXPECT_EQ(decrypt_resp.plaintext(), plaintext_str);
}

TEST(KmsClientTest, AsymmetricDecryptFailureInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeKms> fake, FakeKms::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::AsymmetricDecryptRequest req;
  req.set_name("foo");
  EXPECT_THAT(client->AsymmetricDecrypt(req),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest, AsymmetricSignSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeKms> fake, FakeKms::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(client->kms_stub(), ck.name(), ckv);
  ckv = WaitForEnablement(client->kms_stub(), ckv);

  kms_v1::GetPublicKeyRequest pub_req;
  pub_req.set_name(ckv.name());
  ASSERT_OK_AND_ASSIGN(kms_v1::PublicKey pk, client->GetPublicKey(pub_req));

  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub,
                       ParseX509PublicKeyPem(pk.pem()));

  std::string data = "Here is some data to authenticate";
  uint8_t digest[32];
  SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), digest);

  kms_v1::AsymmetricSignRequest sign_req;
  sign_req.set_name(ckv.name());
  sign_req.mutable_digest()->set_sha256(digest, sizeof(digest));

  ASSERT_OK_AND_ASSIGN(kms_v1::AsymmetricSignResponse sign_resp,
                       client->AsymmetricSign(sign_req));

  EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pub.get());
  ASSERT_OK_AND_ASSIGN(
      std::vector<uint8_t> p1363_sig,
      EcdsaSigAsn1ToP1363(sign_resp.signature(), EC_KEY_get0_group(ec_key)));

  EXPECT_OK(EcdsaVerifyP1363(ec_key, EVP_sha256(), digest, p1363_sig));
}

TEST(KmsClientTest, AsymmetricSignFailureInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeKms> fake, FakeKms::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::AsymmetricSignRequest req;
  req.set_name("foo");
  EXPECT_THAT(client->AsymmetricSign(req),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace kmsp11
