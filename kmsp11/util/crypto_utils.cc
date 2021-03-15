#include "kmsp11/util/crypto_utils.h"

#include <limits>

#include "absl/random/random.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "kmsp11/util/errors.h"
#include "openssl/bn.h"
#include "openssl/bytestring.h"
#include "openssl/crypto.h"
#include "openssl/ec_key.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "openssl/mem.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/x509.h"

namespace kmsp11 {
namespace {

static const ASN1_TIME kUnixEpoch = [] {
  ASN1_TIME time;
  ASN1_TIME_set(&time, absl::ToTimeT(absl::UnixEpoch()));
  return time;
}();

// A helper for invoking an OpenSSL function of the form i2d_FOO, and returning
// the DER output as a string.
template <typename T>
absl::StatusOr<std::string> MarshalDer(T* obj,
                                       int i2d_function(T*, uint8_t**)) {
  int len = i2d_function(obj, nullptr);
  if (len <= 0) {
    return NewInternalError(
        absl::StrCat("failed to compute output length during DER marshaling: ",
                     SslErrorToString()),
        SOURCE_LOCATION);
  }

  std::string result(len, ' ');
  uint8_t* result_data = reinterpret_cast<uint8_t*>(result.data());

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

// A helper for invoking an OpenSSL function of the form d2i_FOO, and returning
// the deserialized object.
template <typename T>
absl::StatusOr<bssl::UniquePtr<T>> ParseDer(
    absl::string_view der_string, T* d2i_function(T**, const uint8_t**, long)) {
  const uint8_t* der_bytes =
      reinterpret_cast<const uint8_t*>(der_string.data());

  bssl::UniquePtr<T> result(
      d2i_function(nullptr, &der_bytes, der_string.size()));
  if (!result) {
    return NewInvalidArgumentError(
        absl::StrCat("error parsing DER: ", SslErrorToString()),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }
  return std::move(result);
}

// A UniformRandomBitGenerator backed by Boring's CSPRNG.
// https://en.cppreference.com/w/cpp/named_req/UniformRandomBitGenerator
class BoringBitGenerator {
 public:
  using result_type = uint64_t;

  static constexpr uint64_t min() {
    return std::numeric_limits<uint64_t>::min();
  }

  static constexpr uint64_t max() {
    return std::numeric_limits<uint64_t>::max();
  }

  uint64_t operator()() {
    uint64_t result;
    RAND_bytes(reinterpret_cast<uint8_t*>(&result), sizeof(result));
    return result;
  }
};

}  // namespace

absl::StatusOr<absl::Time> Asn1TimeToAbsl(const ASN1_TIME* time) {
  int diff_days, diff_secs;
  if (ASN1_TIME_diff(&diff_days, &diff_secs, &kUnixEpoch, time) != 1) {
    return NewInternalError(
        absl::StrCat("error processing ASN1_TIME: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  absl::CivilDay day = absl::CivilDay() + diff_days;
  absl::CivilSecond second = absl::CivilSecond(day) + diff_secs;

  return absl::FromCivil(second, absl::UTCTimeZone());
}

absl::Status CheckFipsSelfTest() {
  if (FIPS_mode() != 1) {
    return absl::FailedPreconditionError(
        absl::StrFormat("FIPS_mode()=%d, want 1", FIPS_mode()));
  }
  int self_test_result = BORINGSSL_self_test();
  if (self_test_result != 1) {
    return absl::InternalError(
        absl::StrFormat("BORINGSSL_self_test()=%d, want 1", self_test_result));
  }
  return absl::OkStatus();
}

absl::StatusOr<const EVP_MD*> DigestForMechanism(CK_MECHANISM_TYPE mechanism) {
  switch (mechanism) {
    case CKM_SHA256:
      return EVP_sha256();
    case CKM_SHA384:
      return EVP_sha384();
    case CKM_SHA512:
      return EVP_sha512();
    default:
      return NewInternalError(
          absl::StrFormat("invalid digest mechanism: %#x", mechanism),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<std::vector<uint8_t>> EcdsaSigAsn1ToP1363(
    absl::string_view asn1_sig, const EC_GROUP* group) {
  bssl::UniquePtr<ECDSA_SIG> sig(ECDSA_SIG_from_bytes(
      reinterpret_cast<const uint8_t*>(asn1_sig.data()), asn1_sig.size()));
  if (!sig) {
    return NewInvalidArgumentError(
        absl::StrCat("error parsing asn.1 signature: ", SslErrorToString()),
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  int sig_len = EcdsaSigLengthP1363(group);
  int n_len = sig_len / 2;
  const BIGNUM *r, *s;
  ECDSA_SIG_get0(sig.get(), &r, &s);

  std::vector<uint8_t> result(sig_len);
  if (!BN_bn2bin_padded(&result[0], n_len, r) ||
      !BN_bn2bin_padded(&result[n_len], n_len, s)) {
    return NewError(
        absl::StatusCode::kOutOfRange,
        absl::StrCat("error marshaling signature value: ", SslErrorToString()),
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  return result;
}

int EcdsaSigLengthP1363(const EC_GROUP* group) {
  return 2 * BN_num_bytes(EC_GROUP_get0_order(group));
}

absl::Status EcdsaVerifyP1363(EC_KEY* public_key, const EVP_MD* hash,
                              absl::Span<const uint8_t> digest,
                              absl::Span<const uint8_t> signature) {
  if (digest.length() != EVP_MD_size(hash)) {
    return NewInvalidArgumentError(
        absl::StrFormat("digest length mismatches expected (got %d, want %d)",
                        digest.length(), EVP_MD_size(hash)),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  if (signature.length() % 2 == 1) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "signature of length %d contains an uneven number of bytes",
            signature.length()),
        CKR_SIGNATURE_LEN_RANGE, SOURCE_LOCATION);
  }

  int max_len = EcdsaSigLengthP1363(EC_KEY_get0_group(public_key));
  if (signature.length() > max_len) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "provided signature length exceeds maximum (got %d, want <= %d)",
            signature.length(), max_len),
        CKR_SIGNATURE_LEN_RANGE, SOURCE_LOCATION);
  }

  bssl::UniquePtr<ECDSA_SIG> sig(ECDSA_SIG_new());
  int n_len = signature.length() / 2;
  if (!BN_bin2bn(&signature[0], n_len, sig->r) ||
      !BN_bin2bn(&signature[n_len], n_len, sig->s)) {
    return NewInternalError(
        absl::StrCat("error parsing signature component: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  if (!ECDSA_do_verify(digest.data(), digest.size(), sig.get(), public_key)) {
    return NewInvalidArgumentError(
        absl::StrCat("verification failed: ", SslErrorToString()),
        CKR_SIGNATURE_INVALID, SOURCE_LOCATION);
  }

  return absl::OkStatus();
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

absl::StatusOr<std::string> MarshalAsn1Integer(ASN1_INTEGER* value) {
  return MarshalDer(value, &i2d_ASN1_INTEGER);
}

absl::StatusOr<std::string> MarshalEcParametersDer(const EC_KEY* key) {
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

absl::StatusOr<std::string> MarshalEcPointDer(const EC_KEY* key) {
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

absl::StatusOr<std::string> MarshalX509CertificateDer(X509* cert) {
  return MarshalDer(cert, &i2d_X509);
}

absl::StatusOr<std::string> MarshalX509Name(X509_NAME* value) {
  return MarshalDer(value, &i2d_X509_NAME);
}

absl::StatusOr<std::string> MarshalX509PublicKeyDer(const EVP_PKEY* key) {
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

absl::StatusOr<std::string> MarshalX509Sig(X509_SIG* value) {
  return MarshalDer(value, &i2d_X509_SIG);
}

absl::StatusOr<bssl::UniquePtr<EVP_PKEY>> ParsePkcs8PrivateKeyPem(
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

absl::StatusOr<bssl::UniquePtr<X509>> ParseX509CertificateDer(
    absl::string_view certificate_der) {
  return ParseDer(certificate_der, &d2i_X509);
}

absl::StatusOr<bssl::UniquePtr<EVP_PKEY>> ParseX509PublicKeyDer(
    absl::string_view public_key_der) {
  return ParseDer(public_key_der, &d2i_PUBKEY);
}

absl::StatusOr<bssl::UniquePtr<EVP_PKEY>> ParseX509PublicKeyPem(
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
  RAND_bytes(reinterpret_cast<uint8_t*>(result.data()), len);
  return result;
}

CK_ULONG RandomHandle() {
  static absl::Mutex bit_generator_mutex;
  static BoringBitGenerator bit_generator ABSL_GUARDED_BY(bit_generator_mutex);

  absl::MutexLock lock(&bit_generator_mutex);
  return absl::Uniform<CK_ULONG>(bit_generator, 1,
                                 std::numeric_limits<CK_ULONG>::max());
}

absl::Status RsaVerifyPkcs1(RSA* public_key, const EVP_MD* hash,
                            absl::Span<const uint8_t> digest,
                            absl::Span<const uint8_t> signature) {
  if (digest.length() != EVP_MD_size(hash)) {
    return NewInvalidArgumentError(
        absl::StrFormat("digest length mismatches expected (got %d, want %d)",
                        digest.length(), EVP_MD_size(hash)),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  if (signature.length() != RSA_size(public_key)) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "signature length mismatches expected (got %d, want %d)",
            signature.length(), RSA_size(public_key)),
        CKR_SIGNATURE_LEN_RANGE, SOURCE_LOCATION);
  }

  if (!RSA_verify(EVP_MD_type(hash), digest.data(), digest.size(),
                  signature.data(), signature.size(), public_key)) {
    return NewInvalidArgumentError(
        absl::StrCat("verification failed: ", SslErrorToString()),
        CKR_SIGNATURE_INVALID, SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

absl::Status RsaVerifyPss(RSA* public_key, const EVP_MD* hash,
                          absl::Span<const uint8_t> digest,
                          absl::Span<const uint8_t> signature) {
  if (digest.length() != EVP_MD_size(hash)) {
    return NewInvalidArgumentError(
        absl::StrFormat("digest length mismatches expected (got %d, want %d)",
                        digest.length(), EVP_MD_size(hash)),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  if (signature.length() != RSA_size(public_key)) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "signature length mismatches expected (got %d, want %d)",
            signature.length(), RSA_size(public_key)),
        CKR_SIGNATURE_LEN_RANGE, SOURCE_LOCATION);
  }

  if (!RSA_verify_pss_mgf1(public_key, digest.data(), digest.size(), hash,
                           nullptr, -1, signature.data(), signature.size())) {
    return NewInvalidArgumentError(
        absl::StrCat("verification failed: ", SslErrorToString()),
        CKR_SIGNATURE_INVALID, SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

absl::Status RsaVerifyRawPkcs1(RSA* public_key, absl::Span<const uint8_t> data,
                               absl::Span<const uint8_t> signature) {
  constexpr size_t kMinRsaKeyBitLength = 2048;
  if (RSA_bits(public_key) < kMinRsaKeyBitLength) {
    return NewInternalError(
        absl::StrFormat("minimum RSA key size is %d bits (got %d)",
                        kMinRsaKeyBitLength, RSA_bits(public_key)),
        SOURCE_LOCATION);
  }

  constexpr size_t kPkcs1OverheadBytes = 11;  // per RFC 3447 section 9.2
  size_t max_data_bytes = RSA_size(public_key) - kPkcs1OverheadBytes;
  if (data.length() > max_data_bytes) {
    return NewInvalidArgumentError(
        absl::StrFormat("data is too large (got %d bytes, want <= %d bytes)",
                        data.length(), max_data_bytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  if (signature.length() != RSA_size(public_key)) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "signature length mismatches expected (got %d, want %d)",
            signature.length(), RSA_size(public_key)),
        CKR_SIGNATURE_LEN_RANGE, SOURCE_LOCATION);
  }

  std::vector<uint8_t> recovered(RSA_size(public_key));
  size_t out_length;
  // Note that RSA_verify_raw is simply public key decryption. It's up to
  // us to verify that `data` matches the decryption result.
  if (!RSA_verify_raw(public_key, &out_length, recovered.data(),
                      recovered.size(), signature.data(), signature.size(),
                      RSA_PKCS1_PADDING)) {
    return NewInvalidArgumentError(
        absl::StrCat("verification failed: ", SslErrorToString()),
        CKR_SIGNATURE_INVALID, SOURCE_LOCATION);
  }

  // TODO(b/160310720): Use a std::equal overload that considers out_length.
  // (See internal version of raw_pkcs1.cc)
  if (out_length != data.size() ||
      !std::equal(data.begin(), data.end(), recovered.begin())) {
    return NewInvalidArgumentError(
        "verification failed: recovered data mismatches expected",
        CKR_SIGNATURE_INVALID, SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

void SafeZeroMemory(volatile char* ptr, size_t size) {
  while (size--) {
    *ptr++ = 0;
  }
}

std::string SslErrorToString() {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  ERR_print_errors(bio.get());
  const uint8_t* buf;
  size_t buf_len;
  if (!BIO_mem_contents(bio.get(), &buf, &buf_len) || buf_len == 0) {
    return "(error could not be retrieved from the SSL stack)";
  }
  return std::string(reinterpret_cast<const char*>(buf), buf_len);
}

}  // namespace kmsp11
