#ifndef KMSP11_ALGORITHM_DETAILS_H_
#define KMSP11_ALGORITHM_DETAILS_H_

#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/util/kms_v1.h"

namespace kmsp11 {

struct AlgorithmDetails {
  kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm;
  kms_v1::CryptoKey::CryptoKeyPurpose purpose;
  std::vector<CK_MECHANISM_TYPE> allowed_mechanisms;
  CK_KEY_TYPE key_type;
  size_t key_bit_length;
  CK_MECHANISM_TYPE key_gen_mechanism;
  absl::optional<CK_MECHANISM_TYPE> digest_mechanism;
};

absl::StatusOr<AlgorithmDetails> GetDetails(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

}  // namespace kmsp11

#endif  // KMSP11_ALGORITHM_DETAILS_H_
