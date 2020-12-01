#include "kmsp11/mechanism.h"

#include "absl/container/flat_hash_map.h"
#include "kmsp11/util/errors.h"

namespace kmsp11 {
namespace {

static const auto* const kMechanisms =
    new absl::flat_hash_map<CK_MECHANISM_TYPE, const CK_MECHANISM_INFO>({
        {
            CKM_ECDSA,
            {
                256,  // ulMinKeySize
                384,  // ulMaxKeySize
                CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE |
                    CKF_EC_UNCOMPRESS  // flags
            },

        },
        {
            CKM_RSA_PKCS,
            {
                2048,                  // ulMinKeySize
                4096,                  // ulMaxKeySize
                CKF_SIGN | CKF_VERIFY  // flags
            },

        },
        {
            CKM_RSA_PKCS_OAEP,
            {
                2048,                      // ulMinKeySize
                4096,                      // ulMaxKeySize
                CKF_DECRYPT | CKF_ENCRYPT  // flags
            },
        },
        {
            CKM_RSA_PKCS_PSS,
            {
                2048,                  // ulMinKeySize
                4096,                  // ulMaxKeySize
                CKF_SIGN | CKF_VERIFY  // flags
            },
        },
    });

}  // namespace

absl::Span<const CK_MECHANISM_TYPE> Mechanisms() {
  static const std::vector<CK_MECHANISM_TYPE>* const kMechanismTypes = [] {
    auto* types = new std::vector<CK_MECHANISM_TYPE>();
    types->reserve(kMechanisms->size());
    for (const auto& entry : *kMechanisms) {
      types->push_back(entry.first);
    }
    std::sort(types->begin(), types->end());
    return types;
  }();
  return *kMechanismTypes;
}

absl::StatusOr<CK_MECHANISM_INFO> MechanismInfo(CK_MECHANISM_TYPE type) {
  const auto& entry = kMechanisms->find(type);
  if (entry == kMechanisms->end()) {
    return NewError(absl::StatusCode::kNotFound,
                    absl::StrFormat("mechanism %#x not found", type),
                    CKR_MECHANISM_INVALID, SOURCE_LOCATION);
  }
  return entry->second;
}

}  // namespace kmsp11
