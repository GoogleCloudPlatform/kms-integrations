#include "kmsp11/util/crypto_utils.h"

#include "kmsp11/util/errors.h"
#include "openssl/bn.h"
#include "openssl/bytestring.h"
#include "openssl/ec_key.h"
#include "openssl/evp.h"
#include "openssl/mem.h"
#include "openssl/pem.h"

namespace kmsp11 {

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

std::string SslErrorToString() {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  ERR_print_errors(bio.get());
  char* buf;
  size_t len = BIO_get_mem_data(bio.get(), &buf);
  return std::string(buf, len);
}

}  // namespace kmsp11
