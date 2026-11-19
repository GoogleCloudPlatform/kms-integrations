// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "kmsp11/util/ml_dsa.h"

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "common/openssl.h"
#include "common/status_macros.h"
#include "kmsp11/util/errors.h"

// ML-DSA verification is only available when building against a BoringSSL
// release that ships <openssl/mldsa.h>. The FIPS-validated BoringSSL and system
// OpenSSL builds do not have it; in those builds signing still works (it is
// performed by Cloud KMS), but local verification is unavailable.
#if defined(OPENSSL_IS_BORINGSSL) && defined(__has_include)
#if __has_include("openssl/mldsa.h")
#include "openssl/bytestring.h"
#include "openssl/mldsa.h"
#define KMSP11_HAVE_MLDSA 1
#endif
#endif

namespace cloud_kms::kmsp11 {
namespace {

// DER encoding of the AlgorithmIdentifier OBJECT IDENTIFIERs from RFC 9881
// (id-ml-dsa-44/65/87 = 2.16.840.1.101.3.4.3.{17,18,19}). The algorithm
// identifiers have absent parameters.
constexpr uint8_t kOidPrefix[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                  0x65, 0x03, 0x04, 0x03};
constexpr uint8_t kOidSuffixMlDsa44 = 0x11;
constexpr uint8_t kOidSuffixMlDsa65 = 0x12;
constexpr uint8_t kOidSuffixMlDsa87 = 0x13;

absl::StatusOr<uint8_t> OidSuffix(CK_ML_DSA_PARAMETER_SET_TYPE parameter_set) {
  switch (parameter_set) {
    case CKP_ML_DSA_44:
      return kOidSuffixMlDsa44;
    case CKP_ML_DSA_65:
      return kOidSuffixMlDsa65;
    case CKP_ML_DSA_87:
      return kOidSuffixMlDsa87;
    default:
      return NewInternalError(
          absl::StrFormat("unknown ML-DSA parameter set %#x", parameter_set),
          SOURCE_LOCATION);
  }
}

void AppendDerLength(std::string* out, size_t len) {
  if (len < 0x80) {
    out->push_back(static_cast<char>(len));
    return;
  }
  std::string len_bytes;
  for (size_t l = len; l > 0; l >>= 8) {
    len_bytes.insert(len_bytes.begin(), static_cast<char>(l & 0xff));
  }
  out->push_back(static_cast<char>(0x80 | len_bytes.size()));
  out->append(len_bytes);
}

void AppendDerTlv(std::string* out, uint8_t tag, std::string_view value) {
  out->push_back(static_cast<char>(tag));
  AppendDerLength(out, value.size());
  out->append(value);
}

// Reads a single DER TLV with the expected tag from the front of `in`, and
// returns its contents. Only definite, minimally-encoded lengths are accepted.
absl::StatusOr<std::string_view> ReadDerTlv(std::string_view* in,
                                            uint8_t expected_tag) {
  auto parse_error = [](std::string_view msg) {
    return NewInvalidArgumentError(
        absl::StrCat("error parsing ML-DSA public key: ", msg),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  };

  if (in->size() < 2) {
    return parse_error("truncated input");
  }
  if (static_cast<uint8_t>((*in)[0]) != expected_tag) {
    return parse_error("unexpected tag");
  }
  size_t pos = 1;
  size_t len = static_cast<uint8_t>((*in)[pos++]);
  if (len & 0x80) {
    size_t num_bytes = len & 0x7f;
    if (num_bytes == 0 || num_bytes > 4 || in->size() < pos + num_bytes) {
      return parse_error("invalid length");
    }
    len = 0;
    for (size_t i = 0; i < num_bytes; i++) {
      len = (len << 8) | static_cast<uint8_t>((*in)[pos++]);
    }
    // Reject non-minimal length encodings.
    if (len < 0x80 || static_cast<uint8_t>((*in)[2]) == 0) {
      return parse_error("non-minimal length");
    }
  }
  if (in->size() - pos < len) {
    return parse_error("truncated input");
  }
  std::string_view contents = in->substr(pos, len);
  in->remove_prefix(pos + len);
  return contents;
}

}  // namespace

absl::StatusOr<MlDsaSizes> GetMlDsaSizes(
    CK_ML_DSA_PARAMETER_SET_TYPE parameter_set) {
  // FIPS 204, Table 2.
  switch (parameter_set) {
    case CKP_ML_DSA_44:
      return MlDsaSizes{1312, 2420};
    case CKP_ML_DSA_65:
      return MlDsaSizes{1952, 3309};
    case CKP_ML_DSA_87:
      return MlDsaSizes{2592, 4627};
    default:
      return NewInternalError(
          absl::StrFormat("unknown ML-DSA parameter set %#x", parameter_set),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<CK_ML_DSA_PARAMETER_SET_TYPE> MlDsaParameterSetForAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  switch (algorithm) {
    case kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_44:
      return CKP_ML_DSA_44;
    case kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_65:
      return CKP_ML_DSA_65;
    case kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_87:
      return CKP_ML_DSA_87;
    default:
      return NewInternalError(
          absl::StrFormat("algorithm %d is not an ML-DSA algorithm", algorithm),
          SOURCE_LOCATION);
  }
}

bool IsMlDsaAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  return MlDsaParameterSetForAlgorithm(algorithm).ok();
}

absl::StatusOr<std::string> MarshalMlDsaPublicKeyDer(
    CK_ML_DSA_PARAMETER_SET_TYPE parameter_set, std::string_view public_key) {
  ASSIGN_OR_RETURN(MlDsaSizes sizes, GetMlDsaSizes(parameter_set));
  if (public_key.size() != sizes.public_key_bytes) {
    return NewInternalError(
        absl::StrFormat("unexpected ML-DSA public key length (got %d, want %d)",
                        public_key.size(), sizes.public_key_bytes),
        SOURCE_LOCATION);
  }
  ASSIGN_OR_RETURN(uint8_t oid_suffix, OidSuffix(parameter_set));

  std::string oid(reinterpret_cast<const char*>(kOidPrefix),
                  sizeof(kOidPrefix));
  oid.push_back(static_cast<char>(oid_suffix));

  std::string algorithm_identifier;
  AppendDerTlv(&algorithm_identifier, 0x30, oid);

  std::string bit_string_contents(1, '\0');  // zero unused bits
  bit_string_contents.append(public_key);

  std::string spki_contents = algorithm_identifier;
  AppendDerTlv(&spki_contents, 0x03, bit_string_contents);

  std::string spki;
  AppendDerTlv(&spki, 0x30, spki_contents);
  return spki;
}

absl::StatusOr<MlDsaPublicKey> ParseMlDsaPublicKeyDer(
    std::string_view public_key_der) {
  auto parse_error = [](std::string_view msg) {
    return NewInvalidArgumentError(
        absl::StrCat("error parsing ML-DSA public key: ", msg),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  };

  std::string_view in = public_key_der;
  ASSIGN_OR_RETURN(std::string_view spki, ReadDerTlv(&in, 0x30));
  if (!in.empty()) {
    return parse_error("trailing data after SubjectPublicKeyInfo");
  }
  ASSIGN_OR_RETURN(std::string_view algorithm_identifier,
                   ReadDerTlv(&spki, 0x30));
  ASSIGN_OR_RETURN(std::string_view bit_string, ReadDerTlv(&spki, 0x03));
  if (!spki.empty()) {
    return parse_error("trailing data in SubjectPublicKeyInfo");
  }

  std::string_view prefix(reinterpret_cast<const char*>(kOidPrefix),
                          sizeof(kOidPrefix));
  // Parameters must be absent, so the AlgorithmIdentifier is just the OID.
  if (algorithm_identifier.size() != prefix.size() + 1 ||
      algorithm_identifier.substr(0, prefix.size()) != prefix) {
    return parse_error("unexpected algorithm identifier");
  }

  MlDsaPublicKey result;
  switch (static_cast<uint8_t>(algorithm_identifier.back())) {
    case kOidSuffixMlDsa44:
      result.parameter_set = CKP_ML_DSA_44;
      break;
    case kOidSuffixMlDsa65:
      result.parameter_set = CKP_ML_DSA_65;
      break;
    case kOidSuffixMlDsa87:
      result.parameter_set = CKP_ML_DSA_87;
      break;
    default:
      return parse_error("unexpected algorithm identifier");
  }

  if (bit_string.empty() || bit_string[0] != '\0') {
    return parse_error("invalid BIT STRING");
  }
  bit_string.remove_prefix(1);

  ASSIGN_OR_RETURN(MlDsaSizes sizes, GetMlDsaSizes(result.parameter_set));
  if (bit_string.size() != sizes.public_key_bytes) {
    return parse_error("unexpected public key length");
  }
  result.value = std::string(bit_string);
  return result;
}

bool MlDsaVerificationSupported() {
#ifdef KMSP11_HAVE_MLDSA
  return true;
#else
  return false;
#endif
}

#ifdef KMSP11_HAVE_MLDSA
namespace {

template <typename PublicKey, auto ParseFn, auto VerifyFn>
absl::Status VerifyWith(const MlDsaPublicKey& public_key,
                        absl::Span<const uint8_t> data,
                        absl::Span<const uint8_t> context,
                        absl::Span<const uint8_t> signature) {
  auto pub = std::make_unique<PublicKey>();
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(public_key.value.data()),
           public_key.value.size());
  if (ParseFn(pub.get(), &cbs) != 1) {
    return NewInternalError("error parsing ML-DSA public key",
                            SOURCE_LOCATION);
  }
  if (VerifyFn(pub.get(), signature.data(), signature.size(), data.data(),
               data.size(), context.data(), context.size()) != 1) {
    return NewInvalidArgumentError("verification failed",
                                   CKR_SIGNATURE_INVALID, SOURCE_LOCATION);
  }
  return absl::OkStatus();
}

}  // namespace
#endif

absl::Status MlDsaVerify(const MlDsaPublicKey& public_key,
                         absl::Span<const uint8_t> data,
                         absl::Span<const uint8_t> context,
                         absl::Span<const uint8_t> signature) {
  ASSIGN_OR_RETURN(MlDsaSizes sizes, GetMlDsaSizes(public_key.parameter_set));
  if (signature.size() != sizes.signature_bytes) {
    return NewInvalidArgumentError(
        absl::StrFormat("signature length mismatch: got %d, want %d",
                        signature.size(), sizes.signature_bytes),
        CKR_SIGNATURE_LEN_RANGE, SOURCE_LOCATION);
  }
  // FIPS 204 limits the context string to 255 bytes.
  if (context.size() > 255) {
    return InvalidMechanismParamError(
        "ML-DSA context strings may not exceed 255 bytes", SOURCE_LOCATION);
  }

#ifdef KMSP11_HAVE_MLDSA
  switch (public_key.parameter_set) {
    case CKP_ML_DSA_44:
      return VerifyWith<MLDSA44_public_key, MLDSA44_parse_public_key,
                        MLDSA44_verify>(public_key, data, context, signature);
    case CKP_ML_DSA_65:
      return VerifyWith<MLDSA65_public_key, MLDSA65_parse_public_key,
                        MLDSA65_verify>(public_key, data, context, signature);
    case CKP_ML_DSA_87:
      return VerifyWith<MLDSA87_public_key, MLDSA87_parse_public_key,
                        MLDSA87_verify>(public_key, data, context, signature);
    default:
      return NewInternalError("unknown ML-DSA parameter set", SOURCE_LOCATION);
  }
#else
  return NewError(absl::StatusCode::kUnimplemented,
                  "ML-DSA verification is not supported by the crypto library "
                  "this module was built with",
                  CKR_MECHANISM_INVALID, SOURCE_LOCATION);
#endif
}

}  // namespace cloud_kms::kmsp11
