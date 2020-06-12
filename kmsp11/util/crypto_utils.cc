#include "kmsp11/util/crypto_utils.h"

#include "absl/time/time.h"
#include "kmsp11/util/errors.h"
#include "openssl/bn.h"
#include "openssl/bytestring.h"
#include "openssl/ec_key.h"
#include "openssl/evp.h"
#include "openssl/mem.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/x509.h"

namespace kmsp11 {
namespace {
static const bssl::UniquePtr<ASN1_TIME> kUnixEpoch(
    ASN1_TIME_set(nullptr, absl::ToTimeT(absl::UnixEpoch())));

// A helper for invoking an OpenSSL function of the form i2d_FOO, and returning
// the DER output as a string.
template <typename T>
StatusOr<std::string> MarshalDer(T* obj, int i2d_function(T*, uint8_t**)) {
  int len = i2d_function(obj, nullptr);
  if (len <= 0) {
    return NewInternalError(
        absl::StrCat("failed to compute output length during DER marshaling: ",
                     SslErrorToString()),
        SOURCE_LOCATION);
  }

  std::string result(len, ' ');
  uint8_t* result_data =
      reinterpret_cast<uint8_t*>(const_cast<char*>(result.data()));

  len = i2d_function(obj, &result_data);
  if (len != result.size()) {
    return NewInternalError(
        absl::StrFormat(
            "length mismatch during DER marshaling (got %d, want %d)", len,
            result.size()),
        SOURCE_LOCATION);
  }

  return result;
}

}  // namespace

StatusOr<absl::Time> Asn1TimeToAbsl(const ASN1_TIME* time) {
  int diff_days, diff_secs;
  if (ASN1_TIME_diff(&diff_days, &diff_secs, kUnixEpoch.get(), time) != 1) {
    return NewInternalError(
        absl::StrCat("error processing ASN1_TIME: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  absl::CivilDay day = absl::CivilDay() + diff_days;
  absl::CivilSecond second = absl::CivilSecond(day) + diff_secs;

  return absl::FromCivil(second, absl::UTCTimeZone());
}

absl::Status EncryptRsaOaep(EVP_PKEY* key, const EVP_MD* hash,
                            absl::Span<const uint8_t> plaintext,
                            absl::Span<uint8_t> ciphertext) {
  if (!key) {
    return NewInvalidArgumentError("missing required argument: key",
                                   CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }
  if (!hash) {
    return NewInvalidArgumentError("missing required argument: hash",
                                   CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }

  const RSA* rsa_key = EVP_PKEY_get0_RSA(key);
  if (!rsa_key) {
    return NewInvalidArgumentError(
        absl::StrFormat("unexpected key type %d provided to EncryptRsaOaep",
                        EVP_PKEY_id(key)),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }

  size_t modulus_size = RSA_size(rsa_key);
  if (ciphertext.size() != modulus_size) {
    return NewInvalidArgumentError(
        absl::StrFormat("unexpected ciphertext size (got %d, want %d)",
                        ciphertext.size(), modulus_size),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }

  // Size limit from https://tools.ietf.org/html/rfc8017#section-7.1.1
  size_t max_plaintext_size = modulus_size - (2 * EVP_MD_size(hash)) - 2;
  if (plaintext.size() > max_plaintext_size) {
    return NewInvalidArgumentError(
        absl::StrFormat("plaintext size %d exceeds maximum %d",
                        plaintext.size(), max_plaintext_size),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(key, nullptr));

  if (!ctx || !EVP_PKEY_encrypt_init(ctx.get()) ||
      !EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) ||
      !EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), hash) ||
      !EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), hash)) {
    return NewInternalError(
        absl::StrCat("error building encryption context: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  size_t out_len = ciphertext.size();
  if (!EVP_PKEY_encrypt(ctx.get(), ciphertext.data(), &out_len,
                        plaintext.data(), plaintext.size())) {
    return NewInternalError(
        absl::StrCat("failed to encrypt: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  if (out_len != modulus_size) {
    std::fill(ciphertext.begin(), ciphertext.end(), 0);
    return NewInternalError(
        absl::StrFormat(
            "actual encrypted length mismatches expected (got %d, expected %d)",
            out_len, modulus_size),
        SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

StatusOr<std::string> MarshalAsn1Integer(ASN1_INTEGER* value) {
  return MarshalDer(value, &i2d_ASN1_INTEGER);
}

StatusOr<std::string> MarshalEcParametersDer(const EC_KEY* key) {
  CBB cbb;
  CBB_zero(&cbb);

  uint8_t* out_bytes;
  size_t out_len;
  if (!CBB_init(&cbb, 0) ||
      !EC_KEY_marshal_curve_name(&cbb, EC_KEY_get0_group(key)) ||
      !CBB_finish(&cbb, &out_bytes, &out_len)) {
    CBB_cleanup(&cbb);
    return NewInternalError(
        absl::StrCat("failed to marshal ec parameters: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  std::string result(reinterpret_cast<char*>(out_bytes), out_len);
  OPENSSL_free(out_bytes);
  return result;
}

StatusOr<std::string> MarshalEcPointDer(const EC_KEY* key) {
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  CBB cbb;
  CBB_zero(&cbb);

  uint8_t* out_bytes;
  size_t out_len;
  if (!CBB_init(&cbb, 0) ||
      !EC_POINT_point2cbb(&cbb, EC_KEY_get0_group(key),
                          EC_KEY_get0_public_key(key),
                          POINT_CONVERSION_UNCOMPRESSED, bn_ctx.get()) ||
      !CBB_finish(&cbb, &out_bytes, &out_len)) {
    CBB_cleanup(&cbb);
    return NewInternalError(
        absl::StrCat("failed to marshal ec point: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  std::string result(reinterpret_cast<char*>(out_bytes), out_len);
  OPENSSL_free(out_bytes);
  return result;
}

StatusOr<std::string> MarshalX509CertificateDer(X509* cert) {
  return MarshalDer(cert, &i2d_X509);
}

StatusOr<std::string> MarshalX509Name(X509_NAME* value) {
  return MarshalDer(value, &i2d_X509_NAME);
}

StatusOr<std::string> MarshalX509PublicKeyDer(const EVP_PKEY* key) {
  CBB cbb;
  CBB_zero(&cbb);

  uint8_t* out_bytes;
  size_t out_len;
  if (!CBB_init(&cbb, 0) || !EVP_marshal_public_key(&cbb, key) ||
      !CBB_finish(&cbb, &out_bytes, &out_len)) {
    CBB_cleanup(&cbb);
    return NewInternalError(
        absl::StrCat("failed to marshal public key: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  std::string result(reinterpret_cast<char*>(out_bytes), out_len);
  OPENSSL_free(out_bytes);
  return result;
}

StatusOr<bssl::UniquePtr<EVP_PKEY>> ParsePkcs8PrivateKeyPem(
    absl::string_view private_key_pem) {
  bssl::UniquePtr<BIO> bio(
      BIO_new_mem_buf(private_key_pem.data(), private_key_pem.size()));
  if (!bio) {
    return NewInternalError(
        absl::StrCat("error allocating bio: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  bssl::UniquePtr<EVP_PKEY> result(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  if (!result) {
    return NewInvalidArgumentError(
        absl::StrCat("error parsing private key: ", SslErrorToString()),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }

  return std::move(result);
}

StatusOr<bssl::UniquePtr<EVP_PKEY>> ParseX509PublicKeyDer(
    absl::string_view public_key_der) {
  const uint8_t* der_bytes =
      reinterpret_cast<const uint8_t*>(public_key_der.data());
  bssl::UniquePtr<EVP_PKEY> result(
      d2i_PUBKEY(nullptr, &der_bytes, public_key_der.size()));

  if (!result) {
    return NewInvalidArgumentError(
        absl::StrCat("error parsing public key: ", SslErrorToString()),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }
  return std::move(result);
}

StatusOr<bssl::UniquePtr<EVP_PKEY>> ParseX509PublicKeyPem(
    absl::string_view public_key_pem) {
  bssl::UniquePtr<BIO> bio(
      BIO_new_mem_buf(public_key_pem.data(), public_key_pem.size()));
  if (!bio) {
    return NewInternalError(
        absl::StrCat("error allocating bio: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  bssl::UniquePtr<EVP_PKEY> result(
      PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
  if (!result) {
    return NewInvalidArgumentError(
        absl::StrCat("error parsing public key: ", SslErrorToString()),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }
  return std::move(result);
}

std::string RandBytes(size_t len) {
  std::string result;
  result.resize(len);
  RAND_bytes(reinterpret_cast<uint8_t*>(const_cast<char*>(result.data())), len);
  return result;
}

std::string SslErrorToString() {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  ERR_print_errors(bio.get());
  char* buf;
  size_t len = BIO_get_mem_data(bio.get(), &buf);
  return std::string(buf, len);
}

uint64_t BoringBitGenerator::operator()() {
  uint64_t result;
  RAND_bytes(reinterpret_cast<uint8_t*>(&result), sizeof(result));
  return result;
}

}  // namespace kmsp11
