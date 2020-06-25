#include "kmsp11/object.h"

#include "absl/strings/str_split.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_macros.h"
#include "openssl/ec_key.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"

namespace kmsp11 {
namespace {

StatusOr<std::string> GetKeyId(absl::string_view version_name) {
  std::vector<std::string> parts = absl::StrSplit(version_name, '/');
  if (parts.size() != 10 || parts[0] != "projects" || parts[2] != "locations" ||
      parts[4] != "keyRings" || parts[6] != "cryptoKeys" ||
      parts[8] != "cryptoKeyVersions") {
    return NewInternalError(
        absl::StrCat("invalid CryptoKeyVersion name: ", version_name),
        SOURCE_LOCATION);
  }
  return parts[7];
}

absl::Status AddStorageAttributes(AttributeMap* attrs,
                                  const kms_v1::CryptoKeyVersion& ckv) {
  ASSIGN_OR_RETURN(std::string key_id, GetKeyId(ckv.name()));

  // 4.4 Storage objects
  attrs->PutBool(CKA_TOKEN, true);
  attrs->PutBool(CKA_PRIVATE, false);
  attrs->PutBool(CKA_MODIFIABLE, false);
  attrs->Put(CKA_LABEL, key_id);
  attrs->PutBool(CKA_COPYABLE, false);
  attrs->PutBool(CKA_DESTROYABLE, false);

  return absl::OkStatus();
};

absl::Status AddKeyAttributes(AttributeMap* attrs,
                              const kms_v1::CryptoKeyVersion& ckv) {
  ASSIGN_OR_RETURN(AlgorithmDetails algorithm, GetDetails(ckv.algorithm()));

  // 4.7 Key objects
  attrs->PutULong(CKA_KEY_TYPE, algorithm.key_type);
  attrs->Put(CKA_ID, ckv.name());
  attrs->Put(CKA_START_DATE, "");
  attrs->Put(CKA_END_DATE, "");
  attrs->PutBool(CKA_DERIVE, false);
  attrs->PutBool(CKA_LOCAL, ckv.import_job().empty());
  attrs->PutULong(CKA_KEY_GEN_MECHANISM, ckv.import_job().empty()
                                             ? algorithm.key_gen_mechanism
                                             : CK_UNAVAILABLE_INFORMATION);
  attrs->PutULongList(CKA_ALLOWED_MECHANISMS, algorithm.allowed_mechanisms);

  return absl::OkStatus();
}

absl::Status AddPublicKeyAttributes(AttributeMap* attrs,
                                    const kms_v1::CryptoKeyVersion& ckv,
                                    absl::string_view public_key_der) {
  ASSIGN_OR_RETURN(AlgorithmDetails algorithm, GetDetails(ckv.algorithm()));

  // 4.8 Public key objects
  attrs->Put(CKA_SUBJECT, "");
  attrs->PutBool(CKA_ENCRYPT,
                 algorithm.purpose == kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
  attrs->PutBool(CKA_VERIFY,
                 algorithm.purpose == kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  attrs->PutBool(CKA_VERIFY_RECOVER, false);
  attrs->PutBool(CKA_WRAP, false);
  attrs->PutBool(CKA_TRUSTED, false);
  attrs->Put(CKA_WRAP_TEMPLATE, "");
  attrs->Put(CKA_PUBLIC_KEY_INFO, public_key_der);
  return absl::OkStatus();
}

absl::Status AddPrivateKeyAttributes(AttributeMap* attrs,
                                     const kms_v1::CryptoKeyVersion& ckv,
                                     absl::string_view public_key_der) {
  ASSIGN_OR_RETURN(AlgorithmDetails algorithm, GetDetails(ckv.algorithm()));

  // 4.9 Private key objects
  attrs->Put(CKA_SUBJECT, "");
  attrs->PutBool(CKA_SENSITIVE, true);
  attrs->PutBool(CKA_DECRYPT,
                 algorithm.purpose == kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
  attrs->PutBool(CKA_SIGN,
                 algorithm.purpose == kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  attrs->PutBool(CKA_SIGN_RECOVER, false);
  attrs->PutBool(CKA_UNWRAP, false);
  attrs->PutBool(CKA_EXTRACTABLE, false);
  attrs->PutBool(CKA_UNWRAP, false);
  attrs->PutBool(CKA_ALWAYS_SENSITIVE, ckv.import_job().empty());
  attrs->PutBool(CKA_NEVER_EXTRACTABLE, ckv.import_job().empty());
  attrs->PutBool(CKA_WRAP_WITH_TRUSTED, false);
  attrs->Put(CKA_UNWRAP_TEMPLATE, "");
  attrs->PutBool(CKA_ALWAYS_AUTHENTICATE, false);
  attrs->Put(CKA_PUBLIC_KEY_INFO, public_key_der);
  return absl::OkStatus();
}

absl::Status AddEcPublicKeyAttributes(AttributeMap* attrs,
                                      const EC_KEY* public_key) {
  ASSIGN_OR_RETURN(std::string params, MarshalEcParametersDer(public_key));
  ASSIGN_OR_RETURN(std::string ec_point, MarshalEcPointDer(public_key));

  // 2.3.3 ECDSA public key objects
  attrs->Put(CKA_EC_PARAMS, params);
  attrs->Put(CKA_EC_POINT, ec_point);

  return absl::OkStatus();
}

absl::Status AddEcPrivateKeyAttributes(AttributeMap* attrs,
                                       const EC_KEY* public_key) {
  ASSIGN_OR_RETURN(std::string params, MarshalEcParametersDer(public_key));

  // 2.3.4 Elliptic curve private key objects
  attrs->Put(CKA_EC_PARAMS, params);
  attrs->PutSensitive(CKA_VALUE);

  // Not required by the spec, but some implementations seem to expect it.
  ASSIGN_OR_RETURN(std::string ec_point, MarshalEcPointDer(public_key));
  attrs->Put(CKA_EC_POINT, ec_point);

  return absl::OkStatus();
}

absl::Status AddRsaPublicKeyAttributes(AttributeMap* attrs,
                                       const RSA* public_key) {
  // 2.1.2 RSA public key objects
  attrs->PutBigNum(CKA_MODULUS, RSA_get0_n(public_key));
  attrs->PutULong(CKA_MODULUS_BITS, RSA_bits(public_key));
  attrs->PutBigNum(CKA_PUBLIC_EXPONENT, RSA_get0_e(public_key));
  return absl::OkStatus();
}

absl::Status AddRsaPrivateKeyAttributes(AttributeMap* attrs,
                                        const RSA* public_key) {
  // 2.1.3 RSA private key objects
  attrs->PutBigNum(CKA_MODULUS, RSA_get0_n(public_key));
  attrs->PutULong(CKA_MODULUS_BITS, RSA_bits(public_key));
  attrs->PutSensitive(CKA_PRIVATE_EXPONENT);
  attrs->PutSensitive(CKA_PRIME_1);
  attrs->PutSensitive(CKA_PRIME_2);
  attrs->PutSensitive(CKA_EXPONENT_1);
  attrs->PutSensitive(CKA_EXPONENT_2);
  attrs->PutSensitive(CKA_COEFFICIENT);

  // Not required by the spec, but some implementations seem to expect it.
  attrs->PutBigNum(CKA_PUBLIC_EXPONENT, RSA_get0_e(public_key));

  return absl::OkStatus();
}

absl::Status AddX509CertificateAttributes(AttributeMap* attrs,
                                          const kms_v1::CryptoKeyVersion& ckv,
                                          X509* cert) {
  ASSIGN_OR_RETURN(absl::Time not_before,
                   Asn1TimeToAbsl(X509_get_notBefore(cert)));
  ASSIGN_OR_RETURN(absl::Time not_after,
                   Asn1TimeToAbsl(X509_get_notAfter(cert)));
  ASSIGN_OR_RETURN(std::string public_key_info,
                   MarshalX509PublicKeyDer(X509_get_pubkey(cert)));

  ASSIGN_OR_RETURN(std::string subject_der,
                   MarshalX509Name(X509_get_subject_name(cert)));
  ASSIGN_OR_RETURN(std::string issuer_der,
                   MarshalX509Name(X509_get_issuer_name(cert)));
  ASSIGN_OR_RETURN(std::string serial,
                   MarshalAsn1Integer(X509_get_serialNumber(cert)));
  ASSIGN_OR_RETURN(std::string cert_der, MarshalX509CertificateDer(cert));

  char cert_der_sha1[20];
  SHA1(reinterpret_cast<const uint8_t*>(cert_der.data()), cert_der.size(),
       reinterpret_cast<uint8_t*>(cert_der_sha1));

  // 4.6.2 Certificate objects
  attrs->PutULong(CKA_CERTIFICATE_TYPE, CKC_X_509);
  attrs->PutBool(CKA_TRUSTED, false);
  attrs->PutULong(CKA_CERTIFICATE_CATEGORY,
                  CK_CERTIFICATE_CATEGORY_UNSPECIFIED);
  attrs->Put(CKA_CHECK_VALUE, absl::string_view(cert_der_sha1, 3));
  attrs->PutDate(CKA_START_DATE, not_before);
  attrs->PutDate(CKA_END_DATE, not_after);
  attrs->Put(CKA_PUBLIC_KEY_INFO, public_key_info);

  // 4.6.3 X.509 public key certificate objects
  attrs->Put(CKA_SUBJECT, subject_der);
  attrs->Put(CKA_ID, ckv.name());
  attrs->Put(CKA_ISSUER, issuer_der);
  attrs->Put(CKA_SERIAL_NUMBER, serial);
  attrs->Put(CKA_VALUE, cert_der);
  attrs->Put(CKA_URL, "");
  attrs->Put(CKA_HASH_OF_SUBJECT_PUBLIC_KEY, "");
  attrs->Put(CKA_HASH_OF_ISSUER_PUBLIC_KEY, "");
  attrs->PutULong(CKA_JAVA_MIDP_SECURITY_DOMAIN,
                  CK_SECURITY_DOMAIN_UNSPECIFIED);

  return absl::OkStatus();
}

}  // namespace

StatusOr<KeyPair> Object::NewKeyPair(
    const google::cloud::kms::v1::CryptoKeyVersion& ckv,
    const EVP_PKEY* public_key) {
  ASSIGN_OR_RETURN(std::string pub_der, MarshalX509PublicKeyDer(public_key));

  AttributeMap pub_attrs;
  pub_attrs.PutULong(CKA_CLASS, CKO_PUBLIC_KEY);
  RETURN_IF_ERROR(AddStorageAttributes(&pub_attrs, ckv));
  RETURN_IF_ERROR(AddKeyAttributes(&pub_attrs, ckv));
  RETURN_IF_ERROR(AddPublicKeyAttributes(&pub_attrs, ckv, pub_der));

  AttributeMap prv_attrs;
  prv_attrs.PutULong(CKA_CLASS, CKO_PRIVATE_KEY);
  RETURN_IF_ERROR(AddStorageAttributes(&prv_attrs, ckv));
  RETURN_IF_ERROR(AddKeyAttributes(&prv_attrs, ckv));
  RETURN_IF_ERROR(AddPrivateKeyAttributes(&prv_attrs, ckv, pub_der));

  int pkey_id = EVP_PKEY_id(public_key);
  switch (pkey_id) {
    case EVP_PKEY_EC: {
      const EC_KEY* ec_public_key = EVP_PKEY_get0_EC_KEY(public_key);
      RETURN_IF_ERROR(AddEcPublicKeyAttributes(&pub_attrs, ec_public_key));
      RETURN_IF_ERROR(AddEcPrivateKeyAttributes(&prv_attrs, ec_public_key));
      break;
    }
    case EVP_PKEY_RSA: {
      const RSA* rsa_public_key = EVP_PKEY_get0_RSA(public_key);
      RETURN_IF_ERROR(AddRsaPublicKeyAttributes(&pub_attrs, rsa_public_key));
      RETURN_IF_ERROR(AddRsaPrivateKeyAttributes(&prv_attrs, rsa_public_key));
      break;
    }
    default:
      return NewError(absl::StatusCode::kUnimplemented,
                      absl::StrFormat("unsupported EVP_PKEY type: %d", pkey_id),
                      CKR_GENERAL_ERROR, SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(AlgorithmDetails algorithm, GetDetails(ckv.algorithm()));
  return KeyPair{Object(ckv.name(), CKO_PUBLIC_KEY, algorithm, pub_attrs),
                 Object(ckv.name(), CKO_PRIVATE_KEY, algorithm, prv_attrs)};
}

StatusOr<Object> Object::NewCertificate(
    const google::cloud::kms::v1::CryptoKeyVersion& ckv, EVP_PKEY* public_key,
    const CertAuthority* cert_authority) {
  ASSIGN_OR_RETURN(std::string key_id, GetKeyId(ckv.name()));
  ASSIGN_OR_RETURN(AlgorithmDetails algorithm, GetDetails(ckv.algorithm()));
  ASSIGN_OR_RETURN(
      bssl::UniquePtr<X509> cert,
      cert_authority->GenerateCert(key_id, public_key, algorithm.purpose));

  AttributeMap cert_attrs;
  cert_attrs.PutULong(CKA_CLASS, CKO_CERTIFICATE);
  RETURN_IF_ERROR(AddStorageAttributes(&cert_attrs, ckv));
  RETURN_IF_ERROR(AddX509CertificateAttributes(&cert_attrs, ckv, cert.get()));

  return Object(ckv.name(), CKO_CERTIFICATE, algorithm, cert_attrs);
}

}  // namespace kmsp11