#ifndef KMSP11_ALGORITHM_DETAILS_H_
#define KMSP11_ALGORITHM_DETAILS_H_

#include "absl/container/flat_hash_set.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/util/status_or.h"

namespace kmsp11 {

struct AlgorithmDetails {
  google::cloud::kms::v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm;
  google::cloud::kms::v1::CryptoKey::CryptoKeyPurpose purpose;
  absl::flat_hash_set<CK_MECHANISM_TYPE> allowed_mechanisms;
  CK_KEY_TYPE key_type;
  size_t key_bit_length;
  CK_MECHANISM_TYPE key_gen_mechanism;
  CK_MECHANISM_TYPE digest_mechanism;
};

StatusOr<AlgorithmDetails> GetDetails(
    google::cloud::kms::v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm
        algorithm);

}  // namespace kmsp11

#endif  // KMSP11_ALGORITHM_DETAILS_H_
