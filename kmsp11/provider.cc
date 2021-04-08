#include "kmsp11/provider.h"

#include "glog/logging.h"
#include "kmsp11/cert_authority.h"
#include "kmsp11/util/kms_client.h"
#include "kmsp11/util/status_macros.h"
#include "kmsp11/util/string_utils.h"
#include "kmsp11/version.h"

namespace kmsp11 {
namespace {

static const char* kDefaultKmsEndpoint = "cloudkms.googleapis.com:443";
constexpr absl::Duration kDefaultRpcTimeout = absl::Seconds(30);

absl::StatusOr<CK_INFO> NewCkInfo() {
  CK_INFO info = {
      {CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR},  // cryptokiVersion
      {0},              // manufacturerID (set with ' ' padding below)
      0,                // flags
      {0},              // libraryDescription (set with ' ' padding below)
      kLibraryVersion,  // libraryVersion
  };
  RETURN_IF_ERROR(CryptokiStrCopy("Google", info.manufacturerID));
  RETURN_IF_ERROR(CryptokiStrCopy("Cryptoki Library for Cloud KMS",
                                  info.libraryDescription));
  return info;
}

std::unique_ptr<KmsClient> NewKmsClient(const LibraryConfig& config) {
  std::string endpoint_address = config.kms_endpoint().empty()
                                     ? kDefaultKmsEndpoint
                                     : config.kms_endpoint();

  std::shared_ptr<grpc::ChannelCredentials> creds =
      config.use_insecure_grpc_channel_credentials()
          ? grpc::InsecureChannelCredentials()
          : grpc::GoogleDefaultCredentials();

  absl::Duration rpc_timeout = config.rpc_timeout_secs() == 0
                                   ? kDefaultRpcTimeout
                                   : absl::Seconds(config.rpc_timeout_secs());

  return absl::make_unique<KmsClient>(endpoint_address, creds, rpc_timeout,
                                      config.user_project_override());
}

}  // namespace

absl::StatusOr<std::unique_ptr<Provider>> Provider::New(LibraryConfig config) {
  ASSIGN_OR_RETURN(CK_INFO info, NewCkInfo());
  std::unique_ptr<KmsClient> client = NewKmsClient(config);

  std::vector<std::unique_ptr<Token>> tokens;
  tokens.reserve(config.tokens_size());
  for (const TokenConfig& tokenConfig : config.tokens()) {
    ASSIGN_OR_RETURN(std::unique_ptr<Token> token,
                     Token::New(tokens.size(), tokenConfig, client.get(),
                                config.experimental_generate_certs()));
    tokens.emplace_back(std::move(token));
  }

  absl::Duration refresh_interval =
      absl::Seconds(config.refresh_interval_secs());
  if (!config.has_refresh_interval_secs()) {
    refresh_interval = absl::Seconds(300);
  }

  // using `new` to invoke a private constructor
  return std::unique_ptr<Provider>(new Provider(
      config, info, std::move(tokens), std::move(client), refresh_interval));
}

absl::StatusOr<Token*> Provider::TokenAt(CK_SLOT_ID slot_id) {
  if (slot_id >= tokens_.size()) {
    return NewError(absl::StatusCode::kNotFound,
                    absl::StrFormat("slot with ID %d does not exist", slot_id),
                    CKR_SLOT_ID_INVALID, SOURCE_LOCATION);
  }
  return tokens_[slot_id].get();
}

absl::StatusOr<CK_SESSION_HANDLE> Provider::OpenSession(
    CK_SLOT_ID slot_id, SessionType session_type) {
  ASSIGN_OR_RETURN(Token * token, TokenAt(slot_id));
  return sessions_.Add(token, session_type, kms_client_.get());
}

absl::StatusOr<std::shared_ptr<Session>> Provider::GetSession(
    CK_SESSION_HANDLE session_handle) {
  return sessions_.Get(session_handle);
}

absl::Status Provider::CloseSession(CK_SESSION_HANDLE session_handle) {
  return sessions_.Remove(session_handle);
}

Provider::Refresher::Refresher(Provider* provider, absl::Duration interval)
    : thread_(
          [](Provider* provider, const absl::Duration interval,
             const absl::Notification* shutdown) {
            while (!shutdown->WaitForNotificationWithTimeout(interval)) {
              for (const std::unique_ptr<Token>& token : provider->tokens_) {
                absl::Status refresh_result =
                    token->RefreshState(*provider->kms_client_);
                if (!refresh_result.ok()) {
                  LOG(ERROR)
                      << "error refreshing state for key ring "
                      << token->key_ring_name() << ": " << refresh_result;
                }
              }
            }
          },
          provider, interval, &shutdown_) {}

Provider::Refresher::~Refresher() {
  shutdown_.Notify();
  thread_.join();
}

}  // namespace kmsp11
