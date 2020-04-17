#include "kmsp11/util/status_utils.h"

#include <cstring>
#include <string>

#include "absl/strings/cord.h"
#include "absl/strings/escaping.h"
#include "absl/types/optional.h"
#include "glog/logging.h"
#include "kmsp11/util/status_details.pb.h"

namespace kmsp11 {

// The URL we'll use for storing a custom payload in the status.
// Notes on the naming convention are at
// https://github.com/abseil/abseil-cpp/blob/bf6166a635ab57fe0559b00dcd3ff09a8c42de2e/absl/status/status.h#L149
static const char* kTypeUrl = "type.googleapis.com/kmsp11.StatusDetails";

void SetErrorRv(absl::Status& status, CK_RV rv) {
  CHECK(!status.ok()) << "attempting to set rv=" << rv << " for status OK";
  CHECK(rv != CKR_OK) << "attempting to set rv=0 for status " << status;
  StatusDetails details;
  details.set_ck_rv(rv);
  status.SetPayload(kTypeUrl, absl::Cord(details.SerializeAsString()));
}

CK_RV GetCkRv(const absl::Status& status) {
  if (status.ok()) {
    return CKR_OK;
  }

  absl::optional<absl::Cord> maybe_payload = status.GetPayload(kTypeUrl);
  if (!maybe_payload.has_value()) {
    return kDefaultErrorCkRv;
  }

  std::string payload(maybe_payload.value());
  StatusDetails details;
  if (!details.ParseFromString(payload)) {
    // It doesn't really make sense to return an error status from a function
    // that is itself processing an error status. Log a warning instead.
    LOG(WARNING) << "status payload of type " << kTypeUrl << " with payload '"
                 << absl::BytesToHexString(payload)
                 << "' could not be parsed as a StatusDetails";
  }

  if (details.ck_rv() == CKR_OK) {
    LOG(WARNING) << "recovered status details has rv=CKR_OK; falling back to "
                    "default error code";
    return kDefaultErrorCkRv;
  }

  return details.ck_rv();
}

}  // namespace kmsp11
