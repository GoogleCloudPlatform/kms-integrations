#include "kmsp11/operation/preconditions.h"

#include "kmsp11/util/errors.h"

namespace kmsp11 {

absl::Status CheckKeyPreconditions(CK_KEY_TYPE key_type,
                                   CK_OBJECT_CLASS object_class,
                                   CK_MECHANISM_TYPE mechanism_type,
                                   Object* object) {
  if (object->algorithm().key_type != key_type) {
    return FailedPreconditionError(
        absl::StrFormat("object %s has type %#x, want %#x",
                        object->kms_key_name(), object->algorithm().key_type,
                        key_type),
        CKR_KEY_TYPE_INCONSISTENT, SOURCE_LOCATION);
  }

  if (object->object_class() != object_class) {
    return FailedPreconditionError(
        absl::StrFormat("object %s has object class %#x, want %#x",
                        object->kms_key_name(), object->object_class(),
                        object_class),
        CKR_KEY_FUNCTION_NOT_PERMITTED, SOURCE_LOCATION);
  }

  const std::vector<CK_MECHANISM_TYPE>& m =
      object->algorithm().allowed_mechanisms;
  if (std::find(m.begin(), m.end(), mechanism_type) == m.end()) {
    return FailedPreconditionError(
        absl::StrFormat("mechanism %#x is not permitted for key %s",
                        mechanism_type, object->kms_key_name()),
        CKR_KEY_FUNCTION_NOT_PERMITTED, SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

}  // namespace kmsp11