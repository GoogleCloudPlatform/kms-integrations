// Copyright 2023 Google LLC
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

#include "kmsp11/main/bridge.h"

#include <fstream>

#include "absl/cleanup/cleanup.h"
#include "fakekms/cpp/fakekms.h"
#include "gmock/gmock.h"
#include "kmsp11/config/config.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/openssl.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/test/test_platform.h"
#include "kmsp11/test/test_status_macros.h"
#include "kmsp11/util/crypto_utils.h"

namespace kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::AnyOf;
using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::Ge;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::IsSupersetOf;
using ::testing::Not;

// TODO(b/254080884): reevaluate use of fixtures and refactor bridge_test.cc to
// improve clarity.
class BridgeTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_server_, fakekms::Server::New());

    auto client = fake_server_->NewClient();
    kr1_ = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr1_);
    kr2_ = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr2_);

    config_file_ = std::tmpnam(nullptr);
    std::ofstream(config_file_) << absl::StrFormat(R"(
tokens:
  - key_ring: "%s"
    label: "foo"
  - key_ring: "%s"
    label: "bar"
kms_endpoint: "%s"
use_insecure_grpc_channel_credentials: true
)",
                                                   kr1_.name(), kr2_.name(),
                                                   fake_server_->listen_addr());

    init_args_ = {0};
    init_args_.flags = CKF_OS_LOCKING_OK;
    init_args_.pReserved = const_cast<char*>(config_file_.c_str());
  }

  void TearDown() override { std::remove(config_file_.c_str()); }

  std::unique_ptr<fakekms::Server> fake_server_;
  kms_v1::KeyRing kr1_;
  kms_v1::KeyRing kr2_;
  std::string config_file_;
  CK_C_INITIALIZE_ARGS init_args_;
};

class AsymmetricSignTest : public BridgeTest {
 protected:
  void SetUp() override {
    BridgeTest::SetUp();
    auto kms_client = fake_server_->NewClient();

    kms_v1::CryptoKey ck;
    ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
    ck.mutable_version_template()->set_algorithm(
        kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
    ck.mutable_version_template()->set_protection_level(
        kms_v1::ProtectionLevel::HSM);
    ck = CreateCryptoKeyOrDie(kms_client.get(), kr1_.name(), "ck", ck, true);

    kms_v1::CryptoKeyVersion ckv;
    ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
    ckv = WaitForEnablement(kms_client.get(), ckv);

    kms_v1::PublicKey pub_proto = GetPublicKey(kms_client.get(), ckv);
    ASSERT_OK_AND_ASSIGN(pub_pkey_, ParseX509PublicKeyPem(pub_proto.pem()));

    EXPECT_OK(Initialize(&init_args_));
    EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session_));

    CK_OBJECT_CLASS object_class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE attr_template[2] = {
        {CKA_ID, const_cast<char*>(ckv.name().data()), ckv.name().size()},
        {CKA_CLASS, &object_class, sizeof(object_class)},
    };
    CK_ULONG found_count;

    EXPECT_OK(FindObjectsInit(session_, attr_template, 2));
    EXPECT_OK(FindObjects(session_, &private_key_, 1, &found_count));
    EXPECT_EQ(found_count, 1);
    EXPECT_OK(FindObjectsFinal(session_));

    object_class = CKO_PUBLIC_KEY;
    EXPECT_OK(FindObjectsInit(session_, attr_template, 2));
    EXPECT_OK(FindObjects(session_, &public_key_, 1, &found_count));
    EXPECT_EQ(found_count, 1);
    EXPECT_OK(FindObjectsFinal(session_))
  }

  void TearDown() override { EXPECT_OK(Finalize(nullptr)); }

  CK_SESSION_HANDLE session_;
  CK_OBJECT_HANDLE private_key_;
  CK_OBJECT_HANDLE public_key_;
  bssl::UniquePtr<EVP_PKEY> pub_pkey_;
};

TEST_F(AsymmetricSignTest, SignVerifySuccess) {
  std::vector<uint8_t> data(128);
  RAND_bytes(data.data(), data.size());

  uint8_t hash[32];
  SHA256(data.data(), data.size(), hash);

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};

  EXPECT_OK(SignInit(session_, &mech, private_key_));

  CK_ULONG signature_size;
  EXPECT_OK(Sign(session_, hash, sizeof(hash), nullptr, &signature_size));
  EXPECT_EQ(signature_size, 64);

  std::vector<uint8_t> signature(signature_size);
  EXPECT_OK(
      Sign(session_, hash, sizeof(hash), signature.data(), &signature_size));

  EXPECT_OK(VerifyInit(session_, &mech, public_key_));
  EXPECT_OK(
      Verify(session_, hash, sizeof(hash), signature.data(), signature.size()));

  // Operation should be terminated after success
  EXPECT_THAT(
      Verify(session_, hash, sizeof(hash), signature.data(), signature.size()),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, SignVerifyMultiPartSuccess) {
  std::vector<uint8_t> data_part1 = {0xDE, 0xAD};
  std::vector<uint8_t> data_part2 = {0xBE, 0xEF};

  CK_MECHANISM mech{CKM_ECDSA_SHA256, nullptr, 0};

  EXPECT_OK(SignInit(session_, &mech, private_key_));

  EXPECT_OK(SignUpdate(session_, data_part1.data(), data_part1.size()));
  EXPECT_OK(SignUpdate(session_, data_part2.data(), data_part2.size()));

  CK_ULONG signature_size;
  EXPECT_OK(SignFinal(session_, nullptr, &signature_size));
  EXPECT_EQ(signature_size, 64);

  std::vector<uint8_t> signature(signature_size);
  EXPECT_OK(SignFinal(session_, signature.data(), &signature_size));

  // Operation should be terminated after success
  EXPECT_THAT(SignUpdate(session_, data_part1.data(), data_part1.size()),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  EXPECT_OK(VerifyInit(session_, &mech, public_key_));

  EXPECT_OK(VerifyUpdate(session_, data_part1.data(), data_part1.size()));
  EXPECT_OK(VerifyUpdate(session_, data_part2.data(), data_part2.size()));

  EXPECT_OK(VerifyFinal(session_, signature.data(), signature_size));

  // Operation should be terminated after success
  EXPECT_THAT(VerifyUpdate(session_, data_part1.data(), data_part1.size()),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, SignHashTooSmall) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));

  uint8_t hash[31], sig[64];
  CK_ULONG signature_size = sizeof(sig);
  EXPECT_THAT(Sign(session_, hash, sizeof(hash), sig, &signature_size),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AsymmetricSignTest, SignSameBuffer) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));

  std::vector<uint8_t> digest(32);
  RAND_bytes(digest.data(), digest.size());

  std::vector<uint8_t> buf(64);
  std::copy(digest.begin(), digest.end(), buf.begin());
  CK_ULONG signature_size = buf.size();

  EXPECT_OK(Sign(session_, buf.data(), 32, buf.data(), &signature_size));

  EXPECT_OK(EcdsaVerifyP1363(EVP_PKEY_get0_EC_KEY(pub_pkey_.get()),
                             EVP_sha256(), digest, buf));
}

TEST_F(AsymmetricSignTest, SignBufferTooSmall) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));

  std::vector<uint8_t> hash(32), sig(63);
  CK_ULONG signature_size = sig.size();
  EXPECT_THAT(
      Sign(session_, hash.data(), hash.size(), sig.data(), &signature_size),
      StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(signature_size, 64);

  sig.resize(signature_size);
  EXPECT_OK(
      Sign(session_, hash.data(), hash.size(), sig.data(), &signature_size));

  // Operation should now be terminated.
  EXPECT_THAT(
      Sign(session_, hash.data(), hash.size(), sig.data(), &signature_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, SignInitFailsInvalidSessionHandle) {
  EXPECT_THAT(SignInit(0, nullptr, 0), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(AsymmetricSignTest, SignInitFailsInvalidKeyHandle) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_THAT(SignInit(session_, &mech, 0), StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_F(AsymmetricSignTest, SignInitFailsOperationActive) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));
  EXPECT_THAT(SignInit(session_, &mech, private_key_),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(AsymmetricSignTest, SignFailsOperationNotInitialized) {
  uint8_t hash[32];
  CK_ULONG signature_size;
  EXPECT_THAT(Sign(session_, hash, sizeof(hash), nullptr, &signature_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, SignUpdateFailsOperationNotInitialized) {
  uint8_t data[32];
  EXPECT_THAT(SignUpdate(session_, data, sizeof(data)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, SignFinalFailsOperationNotInitialized) {
  CK_ULONG signature_size;
  EXPECT_THAT(SignFinal(session_, nullptr, &signature_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, SignFinalFailsWithoutUpdate) {
  CK_MECHANISM mech{CKM_ECDSA_SHA256, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));
  CK_ULONG signature_size = 64;
  std::vector<uint8_t> signature(signature_size);
  EXPECT_THAT(SignFinal(session_, signature.data(), &signature_size),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("SignUpdate needs to be called")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_F(AsymmetricSignTest, SignSinglePartFailsAfterUpdate) {
  CK_MECHANISM mech{CKM_ECDSA_SHA256, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_ULONG signature_size = 64;
  std::vector<uint8_t> signature(signature_size);
  EXPECT_OK(SignUpdate(session_, data.data(), data.size()));
  EXPECT_THAT(Sign(session_, data.data(), data.size(), signature.data(),
                   &signature_size),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("Sign cannot be used to terminate")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_F(AsymmetricSignTest, SignFailsNullHash) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));

  CK_ULONG signature_size;
  EXPECT_THAT(Sign(session_, nullptr, 0, nullptr, &signature_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  std::vector<uint8_t> hash(32), sig(64);
  // Operation should now be terminated.
  EXPECT_THAT(
      Sign(session_, hash.data(), hash.size(), sig.data(), &signature_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, SignUpdateInvalidMechanism) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));
  uint8_t data[32];
  EXPECT_THAT(SignUpdate(session_, data, sizeof(data)),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("does not support multi-part signing")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_F(AsymmetricSignTest, SignFinalInvalidMechanism) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));
  CK_ULONG signature_size = 64;
  std::vector<uint8_t> signature(signature_size);
  EXPECT_THAT(SignFinal(session_, signature.data(), &signature_size),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("does not support multi-part signing")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_F(AsymmetricSignTest, SignInitMacKeysExperimentDisabled) {
  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  EXPECT_THAT(SignInit(session_, &mech, private_key_),
              StatusRvIs(CKR_MECHANISM_INVALID));
}

TEST_F(AsymmetricSignTest, VerifyFailsNullSignatureSize) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session_, &mech, private_key_));

  uint8_t hash[32];
  EXPECT_THAT(Sign(session_, hash, sizeof(hash), nullptr, nullptr),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST_F(AsymmetricSignTest, VerifyInvalidSignature) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));

  uint8_t hash[32], sig[64];
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_SIGNATURE_INVALID));

  // Operation should be terminated after failure
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, VerifyHashTooSmall) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));

  uint8_t hash[31], sig[64];
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_DATA_LEN_RANGE));

  // Operation should be terminated after failure
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, VerifyHashTooLarge) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));

  uint8_t hash[33], sig[64];
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AsymmetricSignTest, VerifySignatureTooSmall) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));

  uint8_t hash[32], sig[63];
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_SIGNATURE_LEN_RANGE));

  // Operation should be terminated after failure
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, VerifySignatureTooLarge) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));

  uint8_t hash[32], sig[65];
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_SIGNATURE_LEN_RANGE));
}

TEST_F(AsymmetricSignTest, VerifyInitFailsInvalidSessionHandle) {
  EXPECT_THAT(VerifyInit(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(AsymmetricSignTest, VerifyInitFailsInvalidKeyHandle) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_THAT(VerifyInit(session_, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_F(AsymmetricSignTest, VerifyInitFailsOperationActive) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));
  EXPECT_THAT(VerifyInit(session_, &mech, public_key_),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(AsymmetricSignTest, VerifyFailsOperationNotInitialized) {
  uint8_t hash[32], sig[64];
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, VerifyUpdateFailsOperationNotInitialized) {
  uint8_t data[32];
  EXPECT_THAT(VerifyUpdate(session_, data, sizeof(data)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, VerifyFinalFailsOperationNotInitialized) {
  CK_ULONG signature_size = 64;
  std::vector<uint8_t> signature(signature_size);
  EXPECT_THAT(VerifyFinal(session_, signature.data(), signature_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, VerifyFinalFailsWithoutUpdate) {
  CK_MECHANISM mech{CKM_ECDSA_SHA256, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));
  CK_ULONG signature_size = 64;
  std::vector<uint8_t> signature(signature_size);
  EXPECT_THAT(VerifyFinal(session_, signature.data(), signature_size),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("VerifyUpdate needs to be called")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_F(AsymmetricSignTest, VerifySinglePartFailsAfterUpdate) {
  CK_MECHANISM mech{CKM_ECDSA_SHA256, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_ULONG signature_size = 64;
  std::vector<uint8_t> signature(signature_size);
  EXPECT_OK(VerifyUpdate(session_, data.data(), data.size()));
  EXPECT_THAT(Verify(session_, data.data(), data.size(), signature.data(),
                     signature_size),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("Verify cannot be used to terminate")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_F(AsymmetricSignTest, VerifyFailsNullHash) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));

  uint8_t sig[64];
  EXPECT_THAT(Verify(session_, nullptr, 0, sig, sizeof(sig)),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  uint8_t hash[32];
  // Operation should be terminated after failure
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, VerifyFailsNullSignature) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));

  uint8_t hash[32];
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), nullptr, 0),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  uint8_t sig[64];
  // Operation should be terminated after failure
  EXPECT_THAT(Verify(session_, hash, sizeof(hash), sig, sizeof(sig)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricSignTest, VerifyUpdateInvalidMechanism) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));
  uint8_t data[32];
  EXPECT_THAT(VerifyUpdate(session_, data, sizeof(data)),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("does not support multi-part verify")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_F(AsymmetricSignTest, VerifyFinalInvalidMechanism) {
  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session_, &mech, public_key_));
  CK_ULONG signature_size = 64;
  std::vector<uint8_t> signature(signature_size);
  EXPECT_THAT(VerifyFinal(session_, signature.data(), signature_size),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("does not support multi-part verify")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_F(AsymmetricSignTest, VerifyInitMacKeysExperimentDisabled) {
  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  EXPECT_THAT(VerifyInit(session_, &mech, private_key_),
              StatusRvIs(CKR_MECHANISM_INVALID));
}

}  // namespace
}  // namespace kmsp11
