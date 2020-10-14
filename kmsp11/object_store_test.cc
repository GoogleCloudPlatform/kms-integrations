#include "kmsp11/object_store.h"

#include "gtest/gtest.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/runfiles.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/status_macros.h"

namespace kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Property;
using ::testing::UnorderedElementsAre;

absl::StatusOr<AsymmetricKey> NewAsymmetricRsaKey() {
  ASSIGN_OR_RETURN(std::string rsa_public_der,
                   LoadTestRunfile("rsa_2048_public.der"));

  AsymmetricKey k;
  k.mutable_crypto_key_version()->set_name(
      "projects/foo/locations/bar/keyRings/baz/cryptoKeys/qux/"
      "cryptoKeyVersions/1");
  k.mutable_crypto_key_version()->set_algorithm(
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  k.set_public_key_der(rsa_public_der);
  k.set_public_key_handle(1001);
  k.set_private_key_handle(1002);
  return k;
}

absl::StatusOr<AsymmetricKey> NewAsymmetricEcKeyAndCert() {
  ASSIGN_OR_RETURN(std::string ec_public_der,
                   LoadTestRunfile("ec_p256_public.der"));
  ASSIGN_OR_RETURN(std::string ec_x509_der,
                   LoadTestRunfile("ec_p256_cert.der"));

  AsymmetricKey k;
  k.mutable_crypto_key_version()->set_name(
      "projects/foo/locations/bar/keyRings/baz/cryptoKeys/luz/"
      "cryptoKeyVersions/1");
  k.mutable_crypto_key_version()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  k.set_public_key_der(ec_public_der);
  k.set_public_key_handle(1003);
  k.set_private_key_handle(1004);
  k.mutable_certificate()->set_handle(1005);
  k.mutable_certificate()->set_x509_der(ec_x509_der);
  return k;
}

TEST(ObjectStoreTest, NewStoreSuccessEmpty) {
  ObjectStoreState s;
  EXPECT_OK(ObjectStore::New(s));
}

TEST(ObjectStoreTest, NewStoreSuccessWithRsaKey) {
  ObjectStoreState s;
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricRsaKey());
  EXPECT_OK(ObjectStore::New(s));
}

TEST(ObjectStoreTest, NewStoreSuccessWithEcKeyAndCertificate) {
  ObjectStoreState s;
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricEcKeyAndCert());
  EXPECT_OK(ObjectStore::New(s));
}

TEST(ObjectStoreTest, NewStoreSuccessWithRsaAndEcKeys) {
  ObjectStoreState s;
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricRsaKey());
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricEcKeyAndCert());
  EXPECT_OK(ObjectStore::New(s));
}

TEST(ObjectStoreTest, NewStoreFailsMissingCryptoKeyVersionName) {
  ObjectStoreState s;
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricRsaKey());

  s.mutable_asymmetric_keys(0)->mutable_crypto_key_version()->clear_name();

  EXPECT_THAT(ObjectStore::New(s),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("invalid CryptoKeyVersion name")));
}

TEST(ObjectStoreTest, NewStoreFailsInvalidCryptoKeyVersionName) {
  ObjectStoreState s;
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricRsaKey());

  s.mutable_asymmetric_keys(0)->mutable_crypto_key_version()->set_name("foo");

  EXPECT_THAT(ObjectStore::New(s),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("invalid CryptoKeyVersion name")));
}

TEST(ObjectStoreTest, NewStoreFailsMissingCryptoKeyVersionAlgorithm) {
  ObjectStoreState s;
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricRsaKey());

  s.mutable_asymmetric_keys(0)->mutable_crypto_key_version()->clear_algorithm();

  EXPECT_THAT(ObjectStore::New(s), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("algorithm not found")));
}

TEST(ObjectStoreTest, NewStoreFailsInvalidCryptoKeyVersionAlgorithm) {
  ObjectStoreState s;
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricRsaKey());

  s.mutable_asymmetric_keys(0)->mutable_crypto_key_version()->set_algorithm(
      kms_v1::CryptoKeyVersion::EXTERNAL_SYMMETRIC_ENCRYPTION);

  EXPECT_THAT(ObjectStore::New(s), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("algorithm not found")));
}

TEST(ObjectStoreTest, NewStoreFailsMissingPublicKey) {
  ObjectStoreState s;
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricRsaKey());

  s.mutable_asymmetric_keys(0)->clear_public_key_der();

  EXPECT_THAT(ObjectStore::New(s), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("error parsing DER")));
}

TEST(ObjectStoreTest, NewStoreFailsInvalidPublicKey) {
  ObjectStoreState s;
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricRsaKey());

  s.mutable_asymmetric_keys(0)->set_public_key_der("foo");

  EXPECT_THAT(ObjectStore::New(s), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("error parsing DER")));
}

TEST(ObjectStoreTest, NewStoreFailsMissingPublicKeyHandle) {
  ObjectStoreState s;
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricRsaKey());

  s.mutable_asymmetric_keys(0)->clear_public_key_handle();

  EXPECT_THAT(ObjectStore::New(s),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("public_key_handle is unset")));
}

TEST(ObjectStoreTest, NewStoreFailsMissingPrivateKeyHandle) {
  ObjectStoreState s;
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricRsaKey());

  s.mutable_asymmetric_keys(0)->clear_private_key_handle();

  EXPECT_THAT(ObjectStore::New(s),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("private_key_handle is unset")));
}

TEST(ObjectStoreTest, NewStoreSuccessMissingCertificate) {
  ObjectStoreState s;
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricEcKeyAndCert());

  s.mutable_asymmetric_keys(0)->clear_certificate();

  EXPECT_OK(ObjectStore::New(s));
}

TEST(ObjectStoreTest, NewStoreFailsCertificateMissingDer) {
  ObjectStoreState s;
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricEcKeyAndCert());

  s.mutable_asymmetric_keys(0)->mutable_certificate()->clear_x509_der();

  EXPECT_THAT(ObjectStore::New(s), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("error parsing DER")));
}

TEST(ObjectStoreTest, NewStoreFailsCertificateInvalidDer) {
  ObjectStoreState s;
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricEcKeyAndCert());

  s.mutable_asymmetric_keys(0)->mutable_certificate()->set_x509_der("foo");

  EXPECT_THAT(ObjectStore::New(s), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("error parsing DER")));
}

TEST(ObjectStoreTest, NewStoreFailsCertificateMissingHandle) {
  ObjectStoreState s;
  ASSERT_OK_AND_ASSIGN(*s.add_asymmetric_keys(), NewAsymmetricEcKeyAndCert());

  s.mutable_asymmetric_keys(0)->mutable_certificate()->clear_handle();

  EXPECT_THAT(ObjectStore::New(s),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("certificate_handle is unset")));
}

TEST(ObjectStoreTest, NewStoreFailsHandleCollision) {
  ObjectStoreState s;

  AsymmetricKey* ec_key = s.add_asymmetric_keys();
  ASSERT_OK_AND_ASSIGN(*ec_key, NewAsymmetricEcKeyAndCert());
  ec_key->mutable_certificate()->set_handle(1);

  AsymmetricKey* rsa_key = s.add_asymmetric_keys();
  ASSERT_OK_AND_ASSIGN(*rsa_key, NewAsymmetricRsaKey());
  rsa_key->set_public_key_handle(1);

  EXPECT_THAT(ObjectStore::New(s),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("duplicate handle detected")));
}

TEST(ObjectStoreTest, GetObjectSuccessPublicKey) {
  ObjectStoreState s;

  AsymmetricKey* key = s.add_asymmetric_keys();
  ASSERT_OK_AND_ASSIGN(*key, NewAsymmetricRsaKey());
  key->set_public_key_handle(1);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectStore> store, ObjectStore::New(s));

  EXPECT_THAT(
      store->GetObject(1),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name,
                   key->crypto_key_version().name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));
}

TEST(ObjectStoreTest, GetObjectSuccessPrivateKey) {
  ObjectStoreState s;

  AsymmetricKey* key = s.add_asymmetric_keys();
  ASSERT_OK_AND_ASSIGN(*key, NewAsymmetricRsaKey());
  key->set_private_key_handle(1);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectStore> store, ObjectStore::New(s));

  EXPECT_THAT(
      store->GetObject(1),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name,
                   key->crypto_key_version().name()),
          Property("object_class", &Object::object_class, CKO_PRIVATE_KEY)))));
}

TEST(ObjectStoreTest, GetObjectSuccessCertificate) {
  ObjectStoreState s;

  AsymmetricKey* key = s.add_asymmetric_keys();
  ASSERT_OK_AND_ASSIGN(*key, NewAsymmetricEcKeyAndCert());
  key->mutable_certificate()->set_handle(1);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectStore> store, ObjectStore::New(s));

  EXPECT_THAT(
      store->GetObject(1),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name,
                   key->crypto_key_version().name()),
          Property("object_class", &Object::object_class, CKO_CERTIFICATE)))));
}

TEST(ObjectStoreTest, GetObjectFailsInvalidHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectStore> store,
                       ObjectStore::New(ObjectStoreState()));

  EXPECT_THAT(store->GetObject(CK_INVALID_HANDLE),
              StatusRvIs(CKR_OBJECT_HANDLE_INVALID));
}

TEST(ObjectStoreTest, GetObjectFailsUnusedHandle) {
  ObjectStoreState s;

  AsymmetricKey* key = s.add_asymmetric_keys();
  ASSERT_OK_AND_ASSIGN(*key, NewAsymmetricEcKeyAndCert());
  ASSERT_NE(key->public_key_handle(), 1);
  ASSERT_NE(key->private_key_handle(), 1);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectStore> store, ObjectStore::New(s));

  EXPECT_THAT(store->GetObject(1), StatusRvIs(CKR_OBJECT_HANDLE_INVALID));
}

TEST(ObjectStoreTest, GetKeySuccessPublicKey) {
  ObjectStoreState s;

  AsymmetricKey* key = s.add_asymmetric_keys();
  ASSERT_OK_AND_ASSIGN(*key, NewAsymmetricRsaKey());
  key->set_public_key_handle(1);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectStore> store, ObjectStore::New(s));

  EXPECT_THAT(
      store->GetKey(1),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name,
                   key->crypto_key_version().name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));
}

TEST(ObjectStoreTest, GetKeySuccessPrivateKey) {
  ObjectStoreState s;

  AsymmetricKey* key = s.add_asymmetric_keys();
  ASSERT_OK_AND_ASSIGN(*key, NewAsymmetricRsaKey());
  key->set_private_key_handle(1);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectStore> store, ObjectStore::New(s));

  EXPECT_THAT(
      store->GetKey(1),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name,
                   key->crypto_key_version().name()),
          Property("object_class", &Object::object_class, CKO_PRIVATE_KEY)))));
}

TEST(ObjectStoreTest, GetKeyFailsCertificate) {
  ObjectStoreState s;

  AsymmetricKey* key = s.add_asymmetric_keys();
  ASSERT_OK_AND_ASSIGN(*key, NewAsymmetricEcKeyAndCert());
  key->mutable_certificate()->set_handle(1);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectStore> store, ObjectStore::New(s));

  // It's a valid /Object/ handle, but it doesn't refer to a key.
  EXPECT_THAT(store->GetKey(1), StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST(ObjectStoreTest, GetKeyFailsInvalidHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectStore> store,
                       ObjectStore::New(ObjectStoreState()));

  EXPECT_THAT(store->GetKey(CK_INVALID_HANDLE),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST(ObjectStoreTest, GetKeyFailsUnusedHandle) {
  ObjectStoreState s;

  AsymmetricKey* key = s.add_asymmetric_keys();
  ASSERT_OK_AND_ASSIGN(*key, NewAsymmetricEcKeyAndCert());
  ASSERT_NE(key->public_key_handle(), 1);
  ASSERT_NE(key->private_key_handle(), 1);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectStore> store, ObjectStore::New(s));

  EXPECT_THAT(store->GetKey(1), StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST(ObjectStoreTest, FindPublicKeysSuccess) {
  ObjectStoreState s;

  AsymmetricKey* ec_key = s.add_asymmetric_keys();
  ASSERT_OK_AND_ASSIGN(*ec_key, NewAsymmetricEcKeyAndCert());
  ec_key->set_public_key_handle(1);

  AsymmetricKey* rsa_key = s.add_asymmetric_keys();
  ASSERT_OK_AND_ASSIGN(*rsa_key, NewAsymmetricRsaKey());
  rsa_key->set_public_key_handle(2);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectStore> store, ObjectStore::New(s));

  EXPECT_THAT(store->Find([](const kmsp11::Object& o) -> bool {
    return o.object_class() == CKO_PUBLIC_KEY;
  }),
              UnorderedElementsAre(1, 2));
}

TEST(ObjectStoreTest, FindWithoutMatchesReturnsEmptyVector) {
  ObjectStoreState s;

  AsymmetricKey* ec_key = s.add_asymmetric_keys();
  ASSERT_OK_AND_ASSIGN(*ec_key, NewAsymmetricEcKeyAndCert());

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectStore> store, ObjectStore::New(s));

  EXPECT_THAT(store->Find([](const kmsp11::Object& o) -> bool {
    return o.algorithm().key_type == CKK_RSA;
  }),
              IsEmpty());
}

TEST(ObjectStoreTest, FindSortsByNameThenClass) {
  ObjectStoreState s;

  AsymmetricKey* ec_key_1 = s.add_asymmetric_keys();
  ASSERT_OK_AND_ASSIGN(*ec_key_1, NewAsymmetricEcKeyAndCert());
  ec_key_1->mutable_crypto_key_version()->set_name(
      "projects/a/locations/b/keyRings/c/cryptoKeys/e/cryptoKeyVersions/1");
  ec_key_1->mutable_certificate()->set_handle(1);
  ec_key_1->set_private_key_handle(2);
  ec_key_1->set_public_key_handle(3);

  AsymmetricKey* ec_key_2 = s.add_asymmetric_keys();
  ASSERT_OK_AND_ASSIGN(*ec_key_2, NewAsymmetricEcKeyAndCert());
  ec_key_2->mutable_crypto_key_version()->set_name(
      "projects/a/locations/b/keyRings/c/cryptoKeys/d/cryptoKeyVersions/1");
  ec_key_2->set_public_key_handle(4);
  ec_key_2->mutable_certificate()->set_handle(5);
  ec_key_2->set_private_key_handle(6);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectStore> store, ObjectStore::New(s));

  EXPECT_THAT(store->Find([](const kmsp11::Object& o) -> bool { return true; }),
              ElementsAre(5,  // (d, CKO_CERTIFICATE==1)
                          4,  // (d, CKO_PUBLIC_KEY==2)
                          6,  // (d, CKO_PRIVATE_KEY==3)
                          1,  // (e, CKO_CERTIFICATE==1)
                          3,  // (e, CKO_PUBLIC_KEY==2)
                          2   // (e, CKO_PRIVATE_KEY==3)
                          ));
}

}  // namespace
}  // namespace kmsp11
