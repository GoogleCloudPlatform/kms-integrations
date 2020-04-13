#include "kmsp11/util/errors.h"

#include "absl/strings/str_cat.h"
#include "glog/logging.h"

namespace kmsp11 {

absl::Status NewError(absl::StatusCode code, absl::string_view msg, CK_RV ck_rv,
                      const SourceLocation& source_location) {
  CHECK(code != absl::StatusCode::kOk)
      << "errors::New cannot be called with code=OK; original location="
      << source_location.ToString();
  CHECK(ck_rv != CKR_OK)
      << "errors::New cannot be called with ck_rv=CKR_OK; original location="
      << source_location.ToString();
  absl::Status status(
      code, absl::StrCat("at ", source_location.ToString(), ": ", msg));
  SetErrorRv(status, ck_rv);
  return status;
}

}  // namespace kmsp11