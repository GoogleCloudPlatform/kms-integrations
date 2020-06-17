#include "kmsp11/operation/kms_signer.h"

#include "kmsp11/util/errors.h"
#include "kmsp11/util/status_macros.h"

namespace kmsp11 {

absl::Status KmsSigner::Sign(KmsClient* client,
                             absl::Span<const uint8_t> digest,
                             absl::Span<uint8_t> signature) {
  size_t expected_digest_size = EVP_MD_size(digest_algorithm());
  if (digest.size() != expected_digest_size) {
    return NewInvalidArgumentError(
        absl::StrFormat("provided digest has incorrect size (got %d, want %d)",
                        digest.size(), expected_digest_size),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  if (signature.size() != signature_length()) {
    return NewInternalError(
        absl::StrFormat(
            "provided signature buffer has incorrect size (got %d, want %d)",
            signature.size(), signature_length()),
        SOURCE_LOCATION);
  }

  kms_v1::AsymmetricSignRequest req;
  req.set_name(std::string(object_->kms_key_name()));

  int digest_nid = EVP_MD_type(digest_algorithm());
  switch (digest_nid) {
    case NID_sha256:
      req.mutable_digest()->set_sha256(digest.data(), digest.size());
      break;
    case NID_sha384:
      req.mutable_digest()->set_sha384(digest.data(), digest.size());
      break;
    case NID_sha512:
      req.mutable_digest()->set_sha512(digest.data(), digest.size());
      break;
    default:
      return NewInternalError(
          absl::StrFormat("unhandled digest type: %d", digest_nid),
          SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(kms_v1::AsymmetricSignResponse resp,
                   client->AsymmetricSign(req));
  RETURN_IF_ERROR(CopySignature(resp.signature(), signature));
  return absl::OkStatus();
}

absl::Status KmsSigner::CopySignature(absl::string_view src,
                                      absl::Span<uint8_t> dest) {
  if (src.size() != signature_length()) {
    return NewInternalError(
        absl::StrFormat("unexpected signature length (got %d, want %d)",
                        src.size(), signature_length()),
        SOURCE_LOCATION);
  }
  std::copy(src.begin(), src.end(), dest.data());
  return absl::OkStatus();
}

}  // namespace kmsp11
