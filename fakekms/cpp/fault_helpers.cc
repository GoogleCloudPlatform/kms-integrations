#include "fakekms/cpp/fault_helpers.h"

#include "fakekms/fault/fault.grpc.pb.h"
#include "glog/logging.h"
#include "grpcpp/grpcpp.h"

namespace fakekms {

namespace {
void AddResponseActionOrDie(const Server& server, absl::string_view method_name,
                            ResponseAction response_action) {
  Fault fault;
  if (!method_name.empty()) {
    fault.mutable_request_matcher()->set_method_name(std::string(method_name));
  }
  *fault.mutable_response_action() = response_action;

  grpc::ClientContext ctx;
  google::protobuf::Empty response;
  grpc::Status result =
      server.NewFaultClient()->AddFault(&ctx, fault, &response);
  CHECK(result.ok()) << "status code: " << result.error_code()
                     << "; message: " << result.error_message();
}

}  // namespace

void AddDelayOrDie(const Server& server, absl::Duration delay,
                   absl::string_view method_name) {
  ResponseAction action;
  // Cribbed directly from util_time::EncodeGoogleApiProto
  const int64_t s = absl::IDivDuration(delay, absl::Seconds(1), &delay);
  const int64_t n = absl::IDivDuration(delay, absl::Nanoseconds(1), &delay);
  action.mutable_delay()->set_seconds(s);
  action.mutable_delay()->set_nanos(n);
  AddResponseActionOrDie(server, method_name, action);
}

void AddErrorOrDie(const Server& server, absl::Status error,
                   absl::string_view method_name) {
  ResponseAction action;
  action.mutable_error()->set_code(error.raw_code());
  action.mutable_error()->set_message(std::string(error.message()));
  AddResponseActionOrDie(server, method_name, action);
}

}  // namespace fakekms
