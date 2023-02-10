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

#include <fstream>

#include "absl/cleanup/cleanup.h"
#include "fakekms/cpp/fakekms.h"
#include "gmock/gmock.h"
#include "kmsp11/config/config.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/main/bridge.h"
#include "kmsp11/openssl.h"
#include "kmsp11/test/common_setup.h"
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

class SymmetricCryptBaseTest
    : public testing::Test,
      public testing::WithParamInterface<
          kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm> {};

class SymmetricCbcCryptTest : public SymmetricCryptBaseTest {};

class SymmetricCtrCryptTest : public SymmetricCryptBaseTest {};

class SymmetricGcmCryptTest : public SymmetricCryptBaseTest {};

const std::array kCbcAlgorithms = {kms_v1::CryptoKeyVersion::AES_128_CBC,
                                   kms_v1::CryptoKeyVersion::AES_256_CBC};

const std::array kCtrAlgorithms = {kms_v1::CryptoKeyVersion::AES_128_CTR,
                                   kms_v1::CryptoKeyVersion::AES_256_CTR};

const std::array kGcmAlgorithms = {kms_v1::CryptoKeyVersion::AES_128_GCM,
                                   kms_v1::CryptoKeyVersion::AES_256_GCM};

INSTANTIATE_TEST_SUITE_P(TestSymmetricEncryption, SymmetricCbcCryptTest,
                         testing::ValuesIn(kCbcAlgorithms));

INSTANTIATE_TEST_SUITE_P(TestSymmetricEncryption, SymmetricCtrCryptTest,
                         testing::ValuesIn(kCtrAlgorithms));

INSTANTIATE_TEST_SUITE_P(TestSymmetricEncryption, SymmetricGcmCryptTest,
                         testing::ValuesIn(kGcmAlgorithms));

TEST_P(SymmetricCbcCryptTest, EncryptDecryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());
  std::vector<uint8_t> iv(16);
  RAND_bytes(iv.data(), iv.size());

  CK_MECHANISM mech = {
      CKM_AES_CBC,  // mechanism
      iv.data(),    // pParameter
      iv.size(),    // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  CK_ULONG ciphertext_size;
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                    &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size());

  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  EXPECT_OK(DecryptInit(session, &mech, secret_key));

  CK_ULONG plaintext_size;
  EXPECT_OK(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                    &plaintext_size));
  EXPECT_EQ(plaintext_size, plaintext.size());

  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(Decrypt(session, ciphertext.data(), ciphertext.size(),
                    recovered_plaintext.data(), &plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricCbcCryptTest, EncryptDecryptMultiPartSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> iv(16);
  RAND_bytes(iv.data(), iv.size());

  CK_MECHANISM mech = {
      CKM_AES_CBC_PAD,  // mechanism
      iv.data(),        // pParameter
      iv.size(),        // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  std::vector<uint8_t> part1(64);
  std::vector<uint8_t> part2(64);
  RAND_bytes(part1.data(), part1.size());
  RAND_bytes(part2.data(), part2.size());
  std::vector<uint8_t> plaintext(part1);
  plaintext.insert(plaintext.end(), part2.begin(), part2.end());

  CK_ULONG ciphertext_size = 144;  // 128 + 16 (full padding block)
  CK_ULONG partial_ciphertext_size = 0;
  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(EncryptUpdate(session, part1.data(), part1.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptUpdate(session, part2.data(), part2.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptFinal(session, ciphertext.data(), &ciphertext_size));

  EXPECT_EQ(ciphertext.size(), ciphertext_size);

  // Operation should be terminated after success
  EXPECT_THAT(
      Encrypt(session, part1.data(), part1.size(), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  EXPECT_OK(DecryptInit(session, &mech, secret_key));

  CK_ULONG plaintext_size = 128;
  CK_ULONG partial_plaintext_size = 0;
  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(DecryptUpdate(session, ciphertext.data(), 16,
                          recovered_plaintext.data(), &partial_plaintext_size));
  EXPECT_EQ(partial_plaintext_size, 0);

  EXPECT_OK(DecryptUpdate(session, ciphertext.data() + 16,
                          ciphertext.size() - 16, recovered_plaintext.data(),
                          &partial_plaintext_size));
  EXPECT_EQ(partial_plaintext_size, 0);

  EXPECT_OK(DecryptFinal(session, recovered_plaintext.data(), &plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricCtrCryptTest, EncryptDecryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

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

  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  CK_ULONG ciphertext_size;
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                    &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size());

  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  EXPECT_OK(DecryptInit(session, &mech, secret_key));

  CK_ULONG plaintext_size;
  EXPECT_OK(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                    &plaintext_size));
  EXPECT_EQ(plaintext_size, plaintext.size());

  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(Decrypt(session, ciphertext.data(), ciphertext.size(),
                    recovered_plaintext.data(), &plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricCtrCryptTest, EncryptDecryptMultiPartSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

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

  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  std::vector<uint8_t> part1(64);
  std::vector<uint8_t> part2(64);
  RAND_bytes(part1.data(), part1.size());
  RAND_bytes(part2.data(), part2.size());
  std::vector<uint8_t> plaintext(part1);
  plaintext.insert(plaintext.end(), part2.begin(), part2.end());

  CK_ULONG ciphertext_size = 128;
  CK_ULONG partial_ciphertext_size = 0;
  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(EncryptUpdate(session, part1.data(), part1.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptUpdate(session, part2.data(), part2.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptFinal(session, ciphertext.data(), &ciphertext_size));

  EXPECT_EQ(ciphertext.size(), ciphertext_size);

  // Operation should be terminated after success
  EXPECT_THAT(
      Encrypt(session, part1.data(), part1.size(), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  EXPECT_OK(DecryptInit(session, &mech, secret_key));

  CK_ULONG plaintext_size = 128;
  CK_ULONG partial_plaintext_size = 0;
  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(DecryptUpdate(session, ciphertext.data(), 16,
                          recovered_plaintext.data(), &partial_plaintext_size));
  EXPECT_EQ(partial_plaintext_size, 0);

  EXPECT_OK(DecryptUpdate(session, ciphertext.data() + 16,
                          ciphertext.size() - 16, recovered_plaintext.data(),
                          &partial_plaintext_size));
  EXPECT_EQ(partial_plaintext_size, 0);

  EXPECT_OK(DecryptFinal(session, recovered_plaintext.data(), &plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptDecryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

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

  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  CK_ULONG ciphertext_size;
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                    &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size() + 16);

  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size() + 16);

  // Operation should be terminated after success
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  EXPECT_OK(DecryptInit(session, &mech, secret_key));

  CK_ULONG plaintext_size;
  EXPECT_OK(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                    &plaintext_size));
  EXPECT_EQ(plaintext_size, plaintext.size());

  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(Decrypt(session, ciphertext.data(), ciphertext.size(),
                    recovered_plaintext.data(), &plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptDecryptMultiPartSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

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

  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  std::vector<uint8_t> part1(64);
  std::vector<uint8_t> part2(64);
  RAND_bytes(part1.data(), part1.size());
  RAND_bytes(part2.data(), part2.size());
  std::vector<uint8_t> plaintext(part1);
  plaintext.insert(plaintext.end(), part2.begin(), part2.end());

  CK_ULONG ciphertext_size = 144;
  CK_ULONG partial_ciphertext_size = 0;
  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(EncryptUpdate(session, part1.data(), part1.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptUpdate(session, part2.data(), part2.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptFinal(session, ciphertext.data(), &ciphertext_size));

  EXPECT_EQ(ciphertext.size(), ciphertext_size);

  // Operation should be terminated after success
  EXPECT_THAT(
      Encrypt(session, part1.data(), part1.size(), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  EXPECT_OK(DecryptInit(session, &mech, secret_key));

  CK_ULONG plaintext_size = 128;
  CK_ULONG partial_plaintext_size = 0;
  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(DecryptUpdate(session, ciphertext.data(), 16,
                          recovered_plaintext.data(), &partial_plaintext_size));
  EXPECT_EQ(partial_plaintext_size, 0);

  EXPECT_OK(DecryptUpdate(session, ciphertext.data() + 16,
                          ciphertext.size() - 16, recovered_plaintext.data(),
                          &partial_plaintext_size));
  EXPECT_EQ(partial_plaintext_size, 0);

  EXPECT_OK(DecryptFinal(session, recovered_plaintext.data(), &plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, DecryptBufferTooSmall) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

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

  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  CK_ULONG ciphertext_size;
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                    &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size() + 16);

  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size() + 16);

  // Operation should be terminated after success
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  EXPECT_OK(DecryptInit(session, &mech, secret_key));

  std::vector<uint8_t> recovered_plaintext(32);
  CK_ULONG plaintext_size = recovered_plaintext.size();
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(),
                      recovered_plaintext.data(), &plaintext_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));

  // Operation should be able to proceed after CKR_BUFFER_TOO_SMALL.
  recovered_plaintext.resize(plaintext_size);
  EXPECT_OK(Decrypt(session, ciphertext.data(), ciphertext.size(),
                    recovered_plaintext.data(), &plaintext_size));
  EXPECT_EQ(plaintext, recovered_plaintext);

  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, DecryptInitFailsInvalidSessionHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server.get());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  EXPECT_THAT(DecryptInit(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_P(SymmetricGcmCryptTest, DecryptInitFailsInvalidKeyHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server.get());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

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

  EXPECT_THAT(DecryptInit(session, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_P(SymmetricGcmCryptTest, DecryptInitFailsOperationActive) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

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

  EXPECT_OK(DecryptInit(session, &mech, secret_key));
  EXPECT_THAT(DecryptInit(session, &mech, secret_key),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_P(SymmetricGcmCryptTest, DecryptFailsOperationNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server.get());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  uint8_t ciphertext[256];
  CK_ULONG plaintext_size;
  EXPECT_THAT(Decrypt(session, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, DecryptFailsNullCiphertext) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

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

  EXPECT_OK(DecryptInit(session, &mech, secret_key));

  CK_ULONG plaintext_size;
  EXPECT_THAT(Decrypt(session, nullptr, 0, nullptr, &plaintext_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  uint8_t ciphertext[256];
  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, DecryptFailsNullPlaintextSize) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

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

  EXPECT_OK(DecryptInit(session, &mech, secret_key));

  uint8_t ciphertext[256];
  EXPECT_THAT(
      Decrypt(session, ciphertext, sizeof(ciphertext), nullptr, nullptr),
      StatusRvIs(CKR_ARGUMENTS_BAD));

  CK_ULONG plaintext_size;
  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

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

  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  CK_ULONG ciphertext_size;
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                    &ciphertext_size));
  EXPECT_EQ(ciphertext_size, plaintext.size() + 16);

  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));

  // Operation should be terminated after success
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptMultiPartSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

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

  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  std::vector<uint8_t> part1(64);
  std::vector<uint8_t> part2(64);
  RAND_bytes(part1.data(), part1.size());
  RAND_bytes(part2.data(), part2.size());

  CK_ULONG ciphertext_size = 144;
  CK_ULONG partial_ciphertext_size = 0;
  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(EncryptUpdate(session, part1.data(), part1.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptUpdate(session, part2.data(), part2.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptFinal(session, ciphertext.data(), &ciphertext_size));

  // Operation should be terminated after success
  EXPECT_THAT(
      Encrypt(session, part1.data(), part1.size(), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptBufferTooSmall) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

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

  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> ciphertext(143);
  CK_ULONG ciphertext_size = ciphertext.size();
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(),
                      ciphertext.data(), &ciphertext_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(ciphertext_size, 144);

  // Operation should be able to proceed after CKR_BUFFER_TOO_SMALL.
  ciphertext.resize(ciphertext_size);
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));

  // Operation should now be terminated.
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptInitFailsInvalidSessionHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server.get());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  EXPECT_THAT(EncryptInit(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_P(SymmetricGcmCryptTest, EncryptInitFailsInvalidKeyHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server.get());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

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

  EXPECT_THAT(EncryptInit(session, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_P(SymmetricGcmCryptTest, EncryptInitFailsOperationActive) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

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

  EXPECT_OK(EncryptInit(session, &mech, secret_key));
  EXPECT_THAT(EncryptInit(session, &mech, secret_key),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_P(SymmetricGcmCryptTest, EncryptFailsOperationNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server.get());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  uint8_t plaintext[32];
  CK_ULONG ciphertext_size;
  EXPECT_THAT(
      Encrypt(session, plaintext, sizeof(plaintext), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptFailsNullPLaintext) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

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

  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  CK_ULONG ciphertext_size;
  EXPECT_THAT(Encrypt(session, nullptr, 0, nullptr, &ciphertext_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  uint8_t plaintext[32];
  // Operation should now be terminated.
  EXPECT_THAT(
      Encrypt(session, plaintext, sizeof(plaintext), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptFailsNullCiphertextSize) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_allow_raw_encryption_keys: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  auto ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,
      GetParam());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

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

  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  uint8_t plaintext[32];
  EXPECT_THAT(Encrypt(session, plaintext, sizeof(plaintext), nullptr, nullptr),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  CK_ULONG ciphertext_size;
  // Operation should now be terminated.
  EXPECT_THAT(
      Encrypt(session, plaintext, sizeof(plaintext), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

}  // namespace
}  // namespace kmsp11
