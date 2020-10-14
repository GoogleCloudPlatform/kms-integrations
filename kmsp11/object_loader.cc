#include "kmsp11/object_loader.h"

#include "glog/logging.h"
#include "kmsp11/algorithm_details.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/status_macros.h"

namespace kmsp11 {
namespace {

static bool IsLoadable(const kms_v1::CryptoKey& key) {
  switch (key.purpose()) {
    case kms_v1::CryptoKey::ASYMMETRIC_DECRYPT:
    case kms_v1::CryptoKey::ASYMMETRIC_SIGN:
      break;
    default:
      LOG(INFO) << "key " << key.name()
                << " is not loadable due to unsupported purpose "
                << key.purpose();
      return false;
  }

  if (key.version_template().protection_level() !=
      kms_v1::ProtectionLevel::HSM) {
    LOG(INFO) << "key " << key.name()
              << " is not loadable due to unsupported protection level "
              << key.version_template().protection_level();
    return false;
  }

  return true;
}

static bool IsLoadable(const kms_v1::CryptoKeyVersion& ckv) {
  if (ckv.state() != kms_v1::CryptoKeyVersion::ENABLED) {
    LOG(INFO) << "version " << ckv.name()
              << " is not loadable due to unsupported state " << ckv.state();
    return false;
  }

  if (!GetDetails(ckv.algorithm()).ok()) {
    LOG(INFO) << "version " << ckv.name()
              << " is not loadable due to unsupported algorithm "
              << ckv.algorithm();
    return false;
  }

  return true;
}

}  // namespace

AsymmetricKey* ObjectLoader::Cache::Get(absl::string_view ckv_name) {
  auto it = keys_.find(ckv_name);
  if (it == keys_.end()) {
    return nullptr;
  }

  return it->second.get();
}

AsymmetricKey* ObjectLoader::Cache::Store(const kms_v1::CryptoKeyVersion& ckv,
                                          absl::string_view public_key_der,
                                          absl::string_view certificate_der) {
  keys_[ckv.name()] = absl::make_unique<AsymmetricKey>();
  AsymmetricKey* key = keys_[ckv.name()].get();

  *key->mutable_crypto_key_version() = ckv;
  key->set_public_key_handle(NewHandle());
  key->set_private_key_handle(NewHandle());
  key->set_public_key_der(std::string(public_key_der));

  if (!certificate_der.empty()) {
    key->mutable_certificate()->set_x509_der(std::string(certificate_der));
    key->mutable_certificate()->set_handle(NewHandle());
  }

  return key;
}

CK_OBJECT_HANDLE ObjectLoader::Cache::NewHandle() {
  CK_OBJECT_HANDLE handle;
  do {
    handle = RandomHandle();
  } while (allocated_handles_.contains(handle));
  allocated_handles_.insert(handle);
  return handle;
}

absl::StatusOr<std::unique_ptr<ObjectLoader>> ObjectLoader::New(
    absl::string_view key_ring_name, bool generate_certs) {
  std::unique_ptr<CertAuthority> cert_authority;
  if (generate_certs) {
    ASSIGN_OR_RETURN(cert_authority, CertAuthority::New());
  }
  return absl::WrapUnique(
      new ObjectLoader(key_ring_name, std::move(cert_authority)));
}

absl::StatusOr<ObjectStoreState> ObjectLoader::BuildState(
    const KmsClient& client) {
  // In the initial implementation of Provider::LoopRefresh, there is no danger
  // of overlapping calls to BuildState. That said, holding the mutex for the
  // duration of BuildState seems like a pretty cheap way to guard against an
  // unintentional change that causes BuildState calls to overlap.
  absl::MutexLock lock(&cache_mutex_);
  ObjectStoreState result;

  kms_v1::ListCryptoKeysRequest req;
  req.set_parent(key_ring_name_);
  CryptoKeysRange keys = client.ListCryptoKeys(req);

  for (CryptoKeysRange::iterator it = keys.begin(); it != keys.end(); it++) {
    ASSIGN_OR_RETURN(kms_v1::CryptoKey key, *it);
    if (!IsLoadable(key)) {
      continue;
    }

    kms_v1::ListCryptoKeyVersionsRequest req;
    req.set_parent(key.name());
    CryptoKeyVersionsRange v = client.ListCryptoKeyVersions(req);

    for (CryptoKeyVersionsRange::iterator it = v.begin(); it != v.end(); it++) {
      ASSIGN_OR_RETURN(kms_v1::CryptoKeyVersion ckv, *it);
      if (!IsLoadable(ckv)) {
        continue;
      }

      AsymmetricKey* key = cache_.Get(ckv.name());
      if (key) {
        *result.add_asymmetric_keys() = *key;
        continue;
      }

      kms_v1::GetPublicKeyRequest pub_req;
      pub_req.set_name(ckv.name());

      ASSIGN_OR_RETURN(kms_v1::PublicKey pub_resp,
                       client.GetPublicKey(pub_req));
      ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> pub,
                       ParseX509PublicKeyPem(pub_resp.pem()));
      ASSIGN_OR_RETURN(std::string public_key_der,
                       MarshalX509PublicKeyDer(pub.get()));

      std::string cert_der;
      if (cert_authority_) {
        ASSIGN_OR_RETURN(bssl::UniquePtr<X509> cert,
                         cert_authority_->GenerateCert(ckv, pub.get()));
        ASSIGN_OR_RETURN(cert_der, MarshalX509CertificateDer(cert.get()));
      }

      *result.add_asymmetric_keys() =
          *cache_.Store(ckv, public_key_der, cert_der);
    }
  }
  return result;
}

}  // namespace kmsp11
