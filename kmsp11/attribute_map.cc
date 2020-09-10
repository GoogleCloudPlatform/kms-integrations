#include "kmsp11/attribute_map.h"

#include "kmsp11/util/errors.h"

namespace kmsp11 {

void AttributeMap::Put(CK_ATTRIBUTE_TYPE type, absl::string_view value) {
  attrs_[type] = std::string(value.data(), value.size());
}

void AttributeMap::PutSensitive(CK_ATTRIBUTE_TYPE type) {
  static constexpr SensitiveValue kSensitiveValue;
  attrs_[type] = kSensitiveValue;
}

bool AttributeMap::Contains(const CK_ATTRIBUTE& attribute) const {
  auto it = attrs_.find(attribute.type);
  if (it == attrs_.end()) {
    return false;
  }
  if (absl::holds_alternative<SensitiveValue>(it->second)) {
    return false;
  }

  return absl::get<std::string>(it->second) ==
         absl::string_view(static_cast<char*>(attribute.pValue),
                           attribute.ulValueLen);
}

absl::StatusOr<absl::string_view> AttributeMap::Value(
    CK_ATTRIBUTE_TYPE type) const {
  auto it = attrs_.find(type);
  if (it == attrs_.end()) {
    return NewError(absl::StatusCode::kNotFound,
                    absl::StrFormat("attribute not found: %#x", type),
                    CKR_ATTRIBUTE_TYPE_INVALID, SOURCE_LOCATION);
  }
  if (absl::holds_alternative<SensitiveValue>(it->second)) {
    return NewError(absl::StatusCode::kPermissionDenied,
                    absl::StrFormat("attribute value sensitive: %#x", type),
                    CKR_ATTRIBUTE_SENSITIVE, SOURCE_LOCATION);
  }
  const std::string& s = absl::get<std::string>(it->second);
  return absl::string_view(s);
}

}  // namespace kmsp11
