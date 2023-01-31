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

class SymmetricCryptBaseTest : public BridgeTest,
  public testing::WithParamInterface<kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm>{
 protected:
  void SetUp() override {
    BridgeTest::SetUp();
    auto kms_client = fake_server_->NewClient();

    kms_v1::CryptoKey ck;
    ck.set_purpose(kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT);
    ck.mutable_version_template()->set_algorithm(GetParam());
    ck.mutable_version_template()->set_protection_level(
        kms_v1::ProtectionLevel::HSM);
    ck = CreateCryptoKeyOrDie(kms_client.get(), kr1_.name(), "ck", ck, true);

    kms_v1::CryptoKeyVersion ckv;
    ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
    ckv = WaitForEnablement(kms_client.get(), ckv);

    std::ofstream(config_file_, std::ofstream::out | std::ofstream::app)
        << "experimental_allow_raw_encryption_keys: true" << std::endl;
    EXPECT_OK(Initialize(&init_args_));
    EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session_));

    CK_OBJECT_CLASS object_class = CKO_SECRET_KEY;
    CK_ATTRIBUTE attr_template[2] = {
        {CKA_ID, const_cast<char*>(ckv.name().data()), ckv.name().size()},
        {CKA_CLASS, &object_class, sizeof(object_class)},
    };
    CK_ULONG found_count;

    EXPECT_OK(FindObjectsInit(session_, attr_template, 2));
    EXPECT_OK(FindObjects(session_, &secret_key_, 1, &found_count));
    EXPECT_EQ(found_count, 1);
    EXPECT_OK(FindObjectsFinal(session_));
  }

  void TearDown() override { EXPECT_OK(Finalize(nullptr)); }

  CK_SESSION_HANDLE session_;
  CK_OBJECT_HANDLE secret_key_;
};

class SymmetricCbcCryptTest : public SymmetricCryptBaseTest {};

class SymmetricCtrCryptTest : public SymmetricCryptBaseTest {};

class SymmetricGcmCryptTest : public SymmetricCryptBaseTest {};

const std::array kCbcAlgorithms = {
    kms_v1::CryptoKeyVersion::AES_128_CBC, kms_v1::CryptoKeyVersion::AES_256_CBC};

const std::array kCtrAlgorithms = {
    kms_v1::CryptoKeyVersion::AES_128_CTR, kms_v1::CryptoKeyVersion::AES_256_CTR};

const std::array kGcmAlgorithms = {
    kms_v1::CryptoKeyVersion::AES_128_GCM, kms_v1::CryptoKeyVersion::AES_256_GCM};

INSTANTIATE_TEST_SUITE_P(TestSymmetricEncryption, SymmetricCbcCryptTest,
                         testing::ValuesIn(kCbcAlgorithms));

INSTANTIATE_TEST_SUITE_P(TestSymmetricEncryption, SymmetricCtrCryptTest,
                         testing::ValuesIn(kCtrAlgorithms));

INSTANTIATE_TEST_SUITE_P(TestSymmetricEncryption, SymmetricGcmCryptTest,
                         testing::ValuesIn(kGcmAlgorithms));

TEST_P(SymmetricCbcCryptTest, EncryptDecryptSuccess) {
  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());
  std::vector<uint8_t> iv(16);
  RAND_bytes(iv.data(), iv.size());

  CK_MECHANISM mech = {
      CKM_AES_CBC,  // mechanism
      iv.data(),    // pParameter
      iv.size(),    // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session_, &mech, secret_key_));

  CK_ULONG ciphertext_size;
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                    &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size());

  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  EXPECT_OK(DecryptInit(session_, &mech, secret_key_));

  CK_ULONG plaintext_size;
  EXPECT_OK(Decrypt(session_, ciphertext.data(), ciphertext.size(), nullptr,
                    &plaintext_size));
  EXPECT_EQ(plaintext_size, plaintext.size());

  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(Decrypt(session_, ciphertext.data(), ciphertext.size(),
                    recovered_plaintext.data(), &plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session_, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricCbcCryptTest, EncryptDecryptMultiPartSuccess) {
  std::vector<uint8_t> iv(16);
  RAND_bytes(iv.data(), iv.size());

  CK_MECHANISM mech = {
      CKM_AES_CBC_PAD,  // mechanism
      iv.data(),        // pParameter
      iv.size(),        // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session_, &mech, secret_key_));

  std::vector<uint8_t> part1(64);
  std::vector<uint8_t> part2(64);
  RAND_bytes(part1.data(), part1.size());
  RAND_bytes(part2.data(), part2.size());
  std::vector<uint8_t> plaintext(part1);
  plaintext.insert(plaintext.end(), part2.begin(), part2.end());

  CK_ULONG ciphertext_size = 144;  // 128 + 16 (full padding block)
  CK_ULONG partial_ciphertext_size = 0;
  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(EncryptUpdate(session_, part1.data(), part1.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptUpdate(session_, part2.data(), part2.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptFinal(session_, ciphertext.data(), &ciphertext_size));

  EXPECT_EQ(ciphertext.size(), ciphertext_size);

  // Operation should be terminated after success
  EXPECT_THAT(
      Encrypt(session_, part1.data(), part1.size(), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  EXPECT_OK(DecryptInit(session_, &mech, secret_key_));

  CK_ULONG plaintext_size = 128;
  CK_ULONG partial_plaintext_size = 0;
  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(DecryptUpdate(session_, ciphertext.data(), 16,
                          recovered_plaintext.data(), &partial_plaintext_size));
  EXPECT_EQ(partial_plaintext_size, 0);

  EXPECT_OK(DecryptUpdate(session_, ciphertext.data() + 16,
                          ciphertext.size() - 16, recovered_plaintext.data(),
                          &partial_plaintext_size));
  EXPECT_EQ(partial_plaintext_size, 0);

  EXPECT_OK(
      DecryptFinal(session_, recovered_plaintext.data(), &plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session_, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricCtrCryptTest, EncryptDecryptSuccess) {
  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());
  std::vector<uint8_t> iv(16);
  RAND_bytes(iv.data(), iv.size());

  CK_AES_CTR_PARAMS params;
  params.ulCounterBits = 128;
  memcpy(params.cb, iv.data(), sizeof(params.cb));

  CK_MECHANISM mech = {
      CKM_AES_CTR,     // mechanism
      &params,         // pParameter
      sizeof(params),  // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session_, &mech, secret_key_));

  CK_ULONG ciphertext_size;
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                    &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size());

  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  EXPECT_OK(DecryptInit(session_, &mech, secret_key_));

  CK_ULONG plaintext_size;
  EXPECT_OK(Decrypt(session_, ciphertext.data(), ciphertext.size(), nullptr,
                    &plaintext_size));
  EXPECT_EQ(plaintext_size, plaintext.size());

  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(Decrypt(session_, ciphertext.data(), ciphertext.size(),
                    recovered_plaintext.data(), &plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session_, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricCtrCryptTest, EncryptDecryptMultiPartSuccess) {
  std::vector<uint8_t> iv(16);
  RAND_bytes(iv.data(), iv.size());

  CK_AES_CTR_PARAMS params;
  params.ulCounterBits = 128;
  memcpy(params.cb, iv.data(), sizeof(params.cb));

  CK_MECHANISM mech = {
      CKM_AES_CTR,     // mechanism
      &params,         // pParameter
      sizeof(params),  // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session_, &mech, secret_key_));

  std::vector<uint8_t> part1(64);
  std::vector<uint8_t> part2(64);
  RAND_bytes(part1.data(), part1.size());
  RAND_bytes(part2.data(), part2.size());
  std::vector<uint8_t> plaintext(part1);
  plaintext.insert(plaintext.end(), part2.begin(), part2.end());

  CK_ULONG ciphertext_size = 128;
  CK_ULONG partial_ciphertext_size = 0;
  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(EncryptUpdate(session_, part1.data(), part1.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptUpdate(session_, part2.data(), part2.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptFinal(session_, ciphertext.data(), &ciphertext_size));

  EXPECT_EQ(ciphertext.size(), ciphertext_size);

  // Operation should be terminated after success
  EXPECT_THAT(
      Encrypt(session_, part1.data(), part1.size(), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  EXPECT_OK(DecryptInit(session_, &mech, secret_key_));

  CK_ULONG plaintext_size = 128;
  CK_ULONG partial_plaintext_size = 0;
  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(DecryptUpdate(session_, ciphertext.data(), 16,
                          recovered_plaintext.data(), &partial_plaintext_size));
  EXPECT_EQ(partial_plaintext_size, 0);

  EXPECT_OK(DecryptUpdate(session_, ciphertext.data() + 16,
                          ciphertext.size() - 16, recovered_plaintext.data(),
                          &partial_plaintext_size));
  EXPECT_EQ(partial_plaintext_size, 0);

  EXPECT_OK(
      DecryptFinal(session_, recovered_plaintext.data(), &plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session_, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptDecryptSuccess) {
  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session_, &mech, secret_key_));

  CK_ULONG ciphertext_size;
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                    &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size() + 16);

  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size() + 16);

  // Operation should be terminated after success
  EXPECT_THAT(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  EXPECT_OK(DecryptInit(session_, &mech, secret_key_));

  CK_ULONG plaintext_size;
  EXPECT_OK(Decrypt(session_, ciphertext.data(), ciphertext.size(), nullptr,
                    &plaintext_size));
  EXPECT_EQ(plaintext_size, plaintext.size());

  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(Decrypt(session_, ciphertext.data(), ciphertext.size(),
                    recovered_plaintext.data(), &plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session_, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptDecryptMultiPartSuccess) {
  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session_, &mech, secret_key_));

  std::vector<uint8_t> part1(64);
  std::vector<uint8_t> part2(64);
  RAND_bytes(part1.data(), part1.size());
  RAND_bytes(part2.data(), part2.size());
  std::vector<uint8_t> plaintext(part1);
  plaintext.insert(plaintext.end(), part2.begin(), part2.end());

  CK_ULONG ciphertext_size = 144;
  CK_ULONG partial_ciphertext_size = 0;
  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(EncryptUpdate(session_, part1.data(), part1.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptUpdate(session_, part2.data(), part2.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptFinal(session_, ciphertext.data(), &ciphertext_size));

  EXPECT_EQ(ciphertext.size(), ciphertext_size);

  // Operation should be terminated after success
  EXPECT_THAT(
      Encrypt(session_, part1.data(), part1.size(), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  EXPECT_OK(DecryptInit(session_, &mech, secret_key_));

  CK_ULONG plaintext_size = 128;
  CK_ULONG partial_plaintext_size = 0;
  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(DecryptUpdate(session_, ciphertext.data(), 16,
                          recovered_plaintext.data(), &partial_plaintext_size));
  EXPECT_EQ(partial_plaintext_size, 0);

  EXPECT_OK(DecryptUpdate(session_, ciphertext.data() + 16,
                          ciphertext.size() - 16, recovered_plaintext.data(),
                          &partial_plaintext_size));
  EXPECT_EQ(partial_plaintext_size, 0);

  EXPECT_OK(
      DecryptFinal(session_, recovered_plaintext.data(), &plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session_, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, DecryptBufferTooSmall) {
  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session_, &mech, secret_key_));

  CK_ULONG ciphertext_size;
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                    &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size() + 16);

  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size() + 16);

  // Operation should be terminated after success
  EXPECT_THAT(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  EXPECT_OK(DecryptInit(session_, &mech, secret_key_));

  std::vector<uint8_t> recovered_plaintext(32);
  CK_ULONG plaintext_size = recovered_plaintext.size();
  EXPECT_THAT(Decrypt(session_, ciphertext.data(), ciphertext.size(),
                      recovered_plaintext.data(), &plaintext_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));

  // Operation should be able to proceed after CKR_BUFFER_TOO_SMALL.
  recovered_plaintext.resize(plaintext_size);
  EXPECT_OK(Decrypt(session_, ciphertext.data(), ciphertext.size(),
                    recovered_plaintext.data(), &plaintext_size));
  EXPECT_EQ(plaintext, recovered_plaintext);

  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session_, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, DecryptInitFailsInvalidSessionHandle) {
  EXPECT_THAT(DecryptInit(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_P(SymmetricGcmCryptTest, DecryptInitFailsInvalidKeyHandle) {
  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_THAT(DecryptInit(session_, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_P(SymmetricGcmCryptTest, DecryptInitFailsOperationActive) {
  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(DecryptInit(session_, &mech, secret_key_));
  EXPECT_THAT(DecryptInit(session_, &mech, secret_key_),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_P(SymmetricGcmCryptTest, DecryptFailsOperationNotInitialized) {
  uint8_t ciphertext[256];
  CK_ULONG plaintext_size;
  EXPECT_THAT(Decrypt(session_, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, DecryptFailsNullCiphertext) {
  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(DecryptInit(session_, &mech, secret_key_));

  CK_ULONG plaintext_size;
  EXPECT_THAT(Decrypt(session_, nullptr, 0, nullptr, &plaintext_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  uint8_t ciphertext[256];
  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session_, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, DecryptFailsNullPlaintextSize) {
  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(DecryptInit(session_, &mech, secret_key_));

  uint8_t ciphertext[256];
  EXPECT_THAT(
      Decrypt(session_, ciphertext, sizeof(ciphertext), nullptr, nullptr),
      StatusRvIs(CKR_ARGUMENTS_BAD));

  CK_ULONG plaintext_size;
  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session_, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptSuccess) {
  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session_, &mech, secret_key_));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  CK_ULONG ciphertext_size;
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                    &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size() + 16);

  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));

  // Operation should be terminated after success
  EXPECT_THAT(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptMultiPartSuccess) {
  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session_, &mech, secret_key_));

  std::vector<uint8_t> part1(64);
  std::vector<uint8_t> part2(64);
  RAND_bytes(part1.data(), part1.size());
  RAND_bytes(part2.data(), part2.size());

  CK_ULONG ciphertext_size = 144;
  CK_ULONG partial_ciphertext_size = 0;
  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(EncryptUpdate(session_, part1.data(), part1.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptUpdate(session_, part2.data(), part2.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptFinal(session_, ciphertext.data(), &ciphertext_size));

  // Operation should be terminated after success
  EXPECT_THAT(
      Encrypt(session_, part1.data(), part1.size(), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptBufferTooSmall) {
  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session_, &mech, secret_key_));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> ciphertext(143);
  CK_ULONG ciphertext_size = ciphertext.size();
  EXPECT_THAT(Encrypt(session_, plaintext.data(), plaintext.size(),
                      ciphertext.data(), &ciphertext_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(ciphertext_size, 144);

  // Operation should be able to proceed after CKR_BUFFER_TOO_SMALL.
  ciphertext.resize(ciphertext_size);
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));

  // Operation should now be terminated.
  EXPECT_THAT(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptInitFailsInvalidSessionHandle) {
  EXPECT_THAT(EncryptInit(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_P(SymmetricGcmCryptTest, EncryptInitFailsInvalidKeyHandle) {
  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_THAT(EncryptInit(session_, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_P(SymmetricGcmCryptTest, EncryptInitFailsOperationActive) {
  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session_, &mech, secret_key_));
  EXPECT_THAT(EncryptInit(session_, &mech, secret_key_),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_P(SymmetricGcmCryptTest, EncryptFailsOperationNotInitialized) {
  uint8_t plaintext[32];
  CK_ULONG ciphertext_size;
  EXPECT_THAT(Encrypt(session_, plaintext, sizeof(plaintext), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptFailsNullPLaintext) {
  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session_, &mech, secret_key_));

  CK_ULONG ciphertext_size;
  EXPECT_THAT(Encrypt(session_, nullptr, 0, nullptr, &ciphertext_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  uint8_t plaintext[32];
  // Operation should now be terminated.
  EXPECT_THAT(Encrypt(session_, plaintext, sizeof(plaintext), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptFailsNullCiphertextSize) {
  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session_, &mech, secret_key_));

  uint8_t plaintext[32];
  EXPECT_THAT(Encrypt(session_, plaintext, sizeof(plaintext), nullptr, nullptr),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  CK_ULONG ciphertext_size;
  // Operation should now be terminated.
  EXPECT_THAT(Encrypt(session_, plaintext, sizeof(plaintext), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

}  // namespace
}  // namespace kmsp11
