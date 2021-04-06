#ifndef FAKEKMS_CPP_FAULT_HELPERS_H_
#define FAKEKMS_CPP_FAULT_HELPERS_H_

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "fakekms/cpp/fakekms.h"
#include "fakekms/fault/fault.grpc.pb.h"

namespace fakekms {

void AddDelayOrDie(const Server& server, absl::Duration delay,
                   absl::string_view method_name = "");

void AddErrorOrDie(const Server& server, absl::Status error,
                   absl::string_view method_name = "");

}  // namespace fakekms

#endif  // FAKEKMS_CPP_FAULT_HELPERS_H_
