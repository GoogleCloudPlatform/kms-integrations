#include "kmsp11/token.h"

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "glog/logging.h"
#include "kmsp11/algorithm_details.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/kms_client.h"
#include "kmsp11/util/status_macros.h"
#include "kmsp11/util/string_utils.h"

namespace kmsp11 {
namespace {

static absl::StatusOr<CK_SLOT_INFO> NewSlotInfo() {
  CK_SLOT_INFO info = {
      {0},                // slotDescription (set with ' ' padding below)
      {0},                // manufacturerID (set with ' ' padding below)
      CKF_TOKEN_PRESENT,  // flags
      {0, 0},             // hardwareVersion
      {0, 0},             // firmwareVersion
  };
  RETURN_IF_ERROR(
      CryptokiStrCopy("A virtual slot mapped to a key ring in Google Cloud KMS",
                      info.slotDescription));
  RETURN_IF_ERROR(CryptokiStrCopy("Google", info.manufacturerID));
  return info;
}

static absl::StatusOr<CK_TOKEN_INFO> NewTokenInfo(
    absl::string_view token_label) {
  CK_TOKEN_INFO info = {
      {0},  // label (set with ' ' padding below)
      {0},  // manufacturerID (set with ' ' padding below)
      {0},  // model (set with ' ' padding below)
      {0},  // serialNumber (set below)
      CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED |
          CKF_SO_PIN_LOCKED,       // flags
      CK_EFFECTIVELY_INFINITE,     // ulMaxSessionCount
      CK_UNAVAILABLE_INFORMATION,  // ulSessionCount
      CK_EFFECTIVELY_INFINITE,     // ulMaxRwSessionCount
      CK_UNAVAILABLE_INFORMATION,  // ulRwSessionCount
      0,                           // ulMaxPinLen
      0,                           // ulMinPinLen
      CK_UNAVAILABLE_INFORMATION,  // ulTotalPublicMemory
      CK_UNAVAILABLE_INFORMATION,  // ulFreePublicMemory
      CK_UNAVAILABLE_INFORMATION,  // ulTotalPrivateMemory
      CK_UNAVAILABLE_INFORMATION,  // ulFreePrivateMemory
      {0, 0},                      // hardwareVersion
      {0, 0},                      // firmwareVersion
      {0}                          // utcTime (set below)
  };
  RETURN_IF_ERROR(CryptokiStrCopy(token_label, info.label));
  RETURN_IF_ERROR(CryptokiStrCopy("Google", info.manufacturerID));
  RETURN_IF_ERROR(CryptokiStrCopy("Cloud KMS Token", info.model));
  RETURN_IF_ERROR(CryptokiStrCopy("", info.serialNumber, '0'));
  RETURN_IF_ERROR(CryptokiStrCopy("", info.utcTime, '0'));
  return info;
}

struct LoadContext {
  KmsClient* client;
  absl::optional<CertAuthority*> cert_authority;
};

static absl::Status AddAsymmetricKeyPair(const LoadContext& ctx,
                                         const kms_v1::CryptoKey& key,
                                         HandleMap<Object>* objects) {
  kms_v1::ListCryptoKeyVersionsRequest req;
  req.set_parent(key.name());
  CryptoKeyVersionsRange v = ctx.client->ListCryptoKeyVersions(req);

  for (CryptoKeyVersionsRange::iterator it = v.begin(); it != v.end(); it++) {
    ASSIGN_OR_RETURN(kms_v1::CryptoKeyVersion ckv, *it);
    if (ckv.state() != kms_v1::CryptoKeyVersion_CryptoKeyVersionState_ENABLED) {
      LOG(INFO) << "skipping version " << ckv.name() << " with state "
                << ckv.state();
      continue;
    }
    if (!GetDetails(ckv.algorithm()).ok()) {
      LOG(INFO) << "skipping version " << ckv.name()
                << " with unsuported algorithm " << ckv.algorithm();
      continue;
    }

    kms_v1::GetPublicKeyRequest pub_req;
    pub_req.set_name(ckv.name());

    ASSIGN_OR_RETURN(kms_v1::PublicKey pub_resp,
                     ctx.client->GetPublicKey(pub_req));
    ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> pub,
                     ParseX509PublicKeyPem(pub_resp.pem()));
    ASSIGN_OR_RETURN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));

    objects->Add(std::move(key_pair.public_key));
    objects->Add(std::move(key_pair.private_key));

    if (ctx.cert_authority.has_value()) {
      ASSIGN_OR_RETURN(
          Object cert,
          Object::NewCertificate(ckv, pub.get(), ctx.cert_authority.value()));
      objects->Add(std::move(cert));
    }
  }

  return absl::OkStatus();
}

static absl::StatusOr<std::unique_ptr<HandleMap<Object>>> LoadObjects(
    const LoadContext& ctx, absl::string_view key_ring_name) {
  auto objects =
      absl::make_unique<HandleMap<Object>>(CKR_OBJECT_HANDLE_INVALID);

  kms_v1::ListCryptoKeysRequest req;
  req.set_parent(std::string(key_ring_name));
  CryptoKeysRange keys = ctx.client->ListCryptoKeys(req);

  for (CryptoKeysRange::iterator it = keys.begin(); it != keys.end(); it++) {
    ASSIGN_OR_RETURN(kms_v1::CryptoKey key, *it);

    if (key.version_template().protection_level() !=
        kms_v1::ProtectionLevel::HSM) {
      LOG(INFO) << "skipping key " << key.name()
                << " with unsupported protection level "
                << key.version_template().protection_level();
      continue;
    }

    switch (key.purpose()) {
      case kms_v1::CryptoKey::ASYMMETRIC_DECRYPT:
      case kms_v1::CryptoKey::ASYMMETRIC_SIGN:
        RETURN_IF_ERROR(AddAsymmetricKeyPair(ctx, key, objects.get()));
        break;
      default:
        LOG(INFO) << "skipping key " << key.name()
                  << " with unsupported purpose " << key.purpose();
        continue;
    }
  }
  return std::move(objects);
}

}  // namespace

absl::StatusOr<std::unique_ptr<Token>> Token::New(CK_SLOT_ID slot_id,
                                                  TokenConfig token_config,
                                                  KmsClient* kms_client,
                                                  bool generate_certs) {
  ASSIGN_OR_RETURN(CK_SLOT_INFO slot_info, NewSlotInfo());
  ASSIGN_OR_RETURN(CK_TOKEN_INFO token_info,
                   NewTokenInfo(token_config.label()));

  LoadContext ctx;
  ctx.client = kms_client;
  ctx.cert_authority = absl::nullopt;

  ASSIGN_OR_RETURN(std::unique_ptr<CertAuthority> cert_authority,
                   CertAuthority::New());
  if (generate_certs) {
    ctx.cert_authority = cert_authority.get();
  }

  ASSIGN_OR_RETURN(std::unique_ptr<HandleMap<Object>> objects,
                   LoadObjects(ctx, token_config.key_ring()));

  // using `new` to invoke a private constructor
  return std::unique_ptr<Token>(
      new Token(slot_id, slot_info, token_info, std::move(objects)));
}

bool Token::is_logged_in() const {
  absl::ReaderMutexLock l(&login_mutex_);
  return is_logged_in_;
}

absl::Status Token::Login(CK_USER_TYPE user) {
  switch (user) {
    case CKU_USER:
      break;
    case CKU_SO:
      return NewError(absl::StatusCode::kPermissionDenied,
                      "login as CKU_SO is not permitted", CKR_PIN_LOCKED,
                      SOURCE_LOCATION);
    case CKU_CONTEXT_SPECIFIC:
      // See description of CKA_ALWAYS_AUTHENTICATE at
      // http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc322855286
      return NewError(absl::StatusCode::kPermissionDenied,
                      "CKA_ALWAYS_AUTHENTICATE is not true on this token",
                      CKR_OPERATION_NOT_INITIALIZED, SOURCE_LOCATION);
    default:
      return NewInvalidArgumentError(
          absl::StrFormat("unknown user type: %#x", user),
          CKR_USER_TYPE_INVALID, SOURCE_LOCATION);
  }

  absl::WriterMutexLock l(&login_mutex_);
  if (is_logged_in_) {
    return FailedPreconditionError("user is already logged in",
                                   CKR_USER_ALREADY_LOGGED_IN, SOURCE_LOCATION);
  }
  is_logged_in_ = true;
  return absl::OkStatus();
}

absl::Status Token::Logout() {
  absl::WriterMutexLock l(&login_mutex_);
  if (!is_logged_in_) {
    return FailedPreconditionError("user is not logged in",
                                   CKR_USER_NOT_LOGGED_IN, SOURCE_LOCATION);
  }
  is_logged_in_ = false;
  return absl::OkStatus();
}

std::vector<CK_OBJECT_HANDLE> Token::FindObjects(
    std::function<bool(const Object&)> predicate) const {
  return objects_->Find(predicate,
                        [](const Object& o1, const Object& o2) -> bool {
                          if (o1.kms_key_name() == o2.kms_key_name()) {
                            return o1.object_class() < o2.object_class();
                          }
                          return o1.kms_key_name() < o2.kms_key_name();
                        });
}

}  // namespace kmsp11
