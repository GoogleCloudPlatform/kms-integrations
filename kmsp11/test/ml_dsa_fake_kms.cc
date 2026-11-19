// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "kmsp11/test/ml_dsa_fake_kms.h"

#include <atomic>

#include "absl/container/flat_hash_map.h"
#include "absl/crc/crc32c.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "common/openssl.h"
#include "google/cloud/kms/v1/service.grpc.pb.h"
#include "grpcpp/grpcpp.h"

#if defined(OPENSSL_IS_BORINGSSL) && defined(__has_include)
#if __has_include("openssl/mldsa.h")
#include "openssl/mldsa.h"
#define KMSP11_HAVE_MLDSA 1
#endif
#endif

namespace cloud_kms::kmsp11 {
namespace {

#ifdef KMSP11_HAVE_MLDSA

int64_t Crc32c(std::string_view data) {
  return static_cast<uint32_t>(absl::ComputeCrc32c(data));
}

struct KeyMaterial {
  kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm;
  std::string public_key;
  std::string seed;
};

template <typename PrivateKey, size_t kPublicKeyBytes, auto GenerateFn>
KeyMaterial Generate(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  auto priv = std::make_unique<PrivateKey>();
  uint8_t pub[kPublicKeyBytes];
  uint8_t seed[MLDSA_SEED_BYTES];
  GenerateFn(pub, seed, priv.get());
  return KeyMaterial{algorithm,
                     std::string(reinterpret_cast<char*>(pub), sizeof(pub)),
                     std::string(reinterpret_cast<char*>(seed), sizeof(seed))};
}

template <typename PrivateKey, size_t kSignatureBytes, auto FromSeedFn,
          auto SignFn>
std::string Sign(const KeyMaterial& key, std::string_view data) {
  auto priv = std::make_unique<PrivateKey>();
  FromSeedFn(priv.get(), reinterpret_cast<const uint8_t*>(key.seed.data()),
             key.seed.size());
  std::string sig(kSignatureBytes, '\0');
  SignFn(reinterpret_cast<uint8_t*>(sig.data()), priv.get(),
         reinterpret_cast<const uint8_t*>(data.data()), data.size(), nullptr,
         0);
  return sig;
}

class Service final : public kms_v1::KeyManagementService::Service {
 public:
  absl::StatusOr<kms_v1::CryptoKeyVersion> CreateKey(
      std::string_view key_ring_name, std::string_view key_id,
      kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
    KeyMaterial material;
    switch (algorithm) {
      case kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_44:
        material = Generate<MLDSA44_private_key, MLDSA44_PUBLIC_KEY_BYTES,
                            MLDSA44_generate_key>(algorithm);
        break;
      case kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_65:
        material = Generate<MLDSA65_private_key, MLDSA65_PUBLIC_KEY_BYTES,
                            MLDSA65_generate_key>(algorithm);
        break;
      case kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_87:
        material = Generate<MLDSA87_private_key, MLDSA87_PUBLIC_KEY_BYTES,
                            MLDSA87_generate_key>(algorithm);
        break;
      default:
        return absl::InvalidArgumentError("not an ML-DSA algorithm");
    }

    kms_v1::CryptoKey ck;
    ck.set_name(absl::StrCat(key_ring_name, "/cryptoKeys/", key_id));
    ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
    ck.mutable_version_template()->set_algorithm(algorithm);
    ck.mutable_version_template()->set_protection_level(
        kms_v1::ProtectionLevel::HSM);

    kms_v1::CryptoKeyVersion ckv;
    ckv.set_name(absl::StrCat(ck.name(), "/cryptoKeyVersions/1"));
    ckv.set_algorithm(algorithm);
    ckv.set_state(kms_v1::CryptoKeyVersion::ENABLED);
    ckv.set_protection_level(kms_v1::ProtectionLevel::HSM);

    absl::MutexLock lock(&mu_);
    keys_[ck.name()] = ck;
    versions_[ck.name()] = ckv;
    material_[ckv.name()] = std::move(material);
    return ckv;
  }

  grpc::Status ListCryptoKeys(grpc::ServerContext*,
                              const kms_v1::ListCryptoKeysRequest* req,
                              kms_v1::ListCryptoKeysResponse* resp) override {
    absl::MutexLock lock(&mu_);
    for (const auto& [name, ck] : keys_) {
      if (absl::StartsWith(name, absl::StrCat(req->parent(), "/"))) {
        *resp->add_crypto_keys() = ck;
      }
    }
    resp->set_total_size(resp->crypto_keys_size());
    return grpc::Status::OK;
  }

  grpc::Status ListCryptoKeyVersions(
      grpc::ServerContext*, const kms_v1::ListCryptoKeyVersionsRequest* req,
      kms_v1::ListCryptoKeyVersionsResponse* resp) override {
    absl::MutexLock lock(&mu_);
    auto it = versions_.find(req->parent());
    if (it != versions_.end()) {
      *resp->add_crypto_key_versions() = it->second;
    }
    resp->set_total_size(resp->crypto_key_versions_size());
    return grpc::Status::OK;
  }

  grpc::Status GetPublicKey(grpc::ServerContext*,
                            const kms_v1::GetPublicKeyRequest* req,
                            kms_v1::PublicKey* resp) override {
    absl::MutexLock lock(&mu_);
    auto it = material_.find(req->name());
    if (it == material_.end()) {
      return grpc::Status(grpc::StatusCode::NOT_FOUND, "key not found");
    }
    // Mirror Cloud KMS: PQC keys are only available in NIST_PQC format.
    if (req->public_key_format() != kms_v1::PublicKey::NIST_PQC) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "public_key_format must be NIST_PQC for PQC keys");
    }
    resp->set_name(req->name());
    resp->set_algorithm(it->second.algorithm);
    resp->set_public_key_format(kms_v1::PublicKey::NIST_PQC);
    resp->mutable_public_key()->set_data(it->second.public_key);
    resp->mutable_public_key()->mutable_crc32c_checksum()->set_value(
        Crc32c(it->second.public_key));
    resp->set_protection_level(kms_v1::ProtectionLevel::HSM);
    return grpc::Status::OK;
  }

  grpc::Status AsymmetricSign(grpc::ServerContext*,
                              const kms_v1::AsymmetricSignRequest* req,
                              kms_v1::AsymmetricSignResponse* resp) override {
    KeyMaterial key;
    {
      absl::MutexLock lock(&mu_);
      auto it = material_.find(req->name());
      if (it == material_.end()) {
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "key not found");
      }
      key = it->second;
    }
    if (req->has_digest()) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "ML-DSA keys require data, not a digest");
    }
    if (req->has_data_crc32c() &&
        req->data_crc32c().value() != Crc32c(req->data())) {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "data_crc32c mismatch");
    }

    std::string sig;
    switch (key.algorithm) {
      case kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_44:
        sig = Sign<MLDSA44_private_key, MLDSA44_SIGNATURE_BYTES,
                   MLDSA44_private_key_from_seed, MLDSA44_sign>(key,
                                                                req->data());
        break;
      case kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_65:
        sig = Sign<MLDSA65_private_key, MLDSA65_SIGNATURE_BYTES,
                   MLDSA65_private_key_from_seed, MLDSA65_sign>(key,
                                                                req->data());
        break;
      case kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_87:
        sig = Sign<MLDSA87_private_key, MLDSA87_SIGNATURE_BYTES,
                   MLDSA87_private_key_from_seed, MLDSA87_sign>(key,
                                                                req->data());
        break;
      default:
        return grpc::Status(grpc::StatusCode::INTERNAL, "bad algorithm");
    }
    if (corrupt_signatures_) {
      sig[0] ^= 0x01;
    }
    sign_count_++;

    resp->set_name(req->name());
    resp->set_signature(sig);
    resp->mutable_signature_crc32c()->set_value(Crc32c(sig));
    resp->set_verified_data_crc32c(req->has_data_crc32c());
    resp->set_protection_level(kms_v1::ProtectionLevel::HSM);
    return grpc::Status::OK;
  }

  std::atomic<int> sign_count_ = 0;
  std::atomic<bool> corrupt_signatures_ = false;

 private:
  absl::Mutex mu_;
  absl::flat_hash_map<std::string, kms_v1::CryptoKey> keys_
      ABSL_GUARDED_BY(mu_);
  absl::flat_hash_map<std::string, kms_v1::CryptoKeyVersion> versions_
      ABSL_GUARDED_BY(mu_);
  absl::flat_hash_map<std::string, KeyMaterial> material_ ABSL_GUARDED_BY(mu_);
};

class MlDsaFakeKmsImpl : public MlDsaFakeKms {
 public:
  MlDsaFakeKmsImpl() {
    grpc::ServerBuilder builder;
    int port = 0;
    builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(),
                             &port);
    builder.RegisterService(&service_);
    server_ = builder.BuildAndStart();
    listen_addr_ = absl::StrCat("127.0.0.1:", port);
  }

  ~MlDsaFakeKmsImpl() override {
    if (server_) {
      server_->Shutdown();
    }
  }

  bool ok() const { return server_ != nullptr; }

  const std::string& listen_addr() const override { return listen_addr_; }

  absl::StatusOr<kms_v1::CryptoKeyVersion> CreateKey(
      std::string_view key_ring_name, std::string_view key_id,
      kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) override {
    return service_.CreateKey(key_ring_name, key_id, algorithm);
  }

  int sign_count() const override { return service_.sign_count_; }

  void set_corrupt_signatures(bool corrupt) override {
    service_.corrupt_signatures_ = corrupt;
  }

 private:
  Service service_;
  std::unique_ptr<grpc::Server> server_;
  std::string listen_addr_;
};

#endif  // KMSP11_HAVE_MLDSA

}  // namespace

absl::StatusOr<std::unique_ptr<MlDsaFakeKms>> MlDsaFakeKms::New() {
#ifdef KMSP11_HAVE_MLDSA
  auto fake = std::make_unique<MlDsaFakeKmsImpl>();
  if (!fake->ok()) {
    return absl::InternalError("failed to start ML-DSA fake KMS server");
  }
  return fake;
#else
  return absl::UnimplementedError(
      "the crypto library does not support ML-DSA");
#endif
}

}  // namespace cloud_kms::kmsp11
