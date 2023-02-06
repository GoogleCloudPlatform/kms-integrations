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

TEST(AsymmetricCryptTest, DecryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  kms_v1::CryptoKeyVersion ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_pkey,
                       GetEVPPublicKey(fake_server.get(), ckv));

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  uint8_t ciphertext[256];
  EXPECT_OK(EncryptRsaOaep(pub_pkey.get(), EVP_sha256(), plaintext,
                           absl::MakeSpan(ciphertext)));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};
  EXPECT_OK(DecryptInit(session, &mech, private_key));

  CK_ULONG plaintext_size;
  EXPECT_OK(Decrypt(session, ciphertext, sizeof(ciphertext), nullptr,
                    &plaintext_size));
  EXPECT_EQ(plaintext_size, plaintext.size());

  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(Decrypt(session, ciphertext, sizeof(ciphertext),
                    recovered_plaintext.data(), &plaintext_size));
  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST(AsymmetricCryptTest, DecryptSuccessSameBuffer) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  kms_v1::CryptoKeyVersion ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_pkey,
                       GetEVPPublicKey(fake_server.get(), ckv));

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> buf(256);
  EXPECT_OK(EncryptRsaOaep(pub_pkey.get(), EVP_sha256(), plaintext,
                           absl::MakeSpan(buf)));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};
  EXPECT_OK(DecryptInit(session, &mech, private_key));

  CK_ULONG plaintext_size = buf.size();
  EXPECT_OK(
      Decrypt(session, buf.data(), buf.size(), buf.data(), &plaintext_size));
  EXPECT_EQ(plaintext_size, plaintext.size());

  buf.resize(plaintext_size);
  EXPECT_EQ(buf, plaintext);
}

TEST(AsymmetricCryptTest, DecryptBufferTooSmall) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  kms_v1::CryptoKeyVersion ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_pkey,
                       GetEVPPublicKey(fake_server.get(), ckv));

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  uint8_t ciphertext[256];
  EXPECT_OK(EncryptRsaOaep(pub_pkey.get(), EVP_sha256(), plaintext,
                           absl::MakeSpan(ciphertext)));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};
  EXPECT_OK(DecryptInit(session, &mech, private_key));

  std::vector<uint8_t> recovered_plaintext(32);
  CK_ULONG plaintext_size = recovered_plaintext.size();
  EXPECT_THAT(Decrypt(session, ciphertext, sizeof(ciphertext),
                      recovered_plaintext.data(), &plaintext_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be able to proceed after CKR_BUFFER_TOO_SMALL.
  recovered_plaintext.resize(plaintext_size);
  EXPECT_OK(Decrypt(session, ciphertext, sizeof(ciphertext),
                    recovered_plaintext.data(), &plaintext_size));
  EXPECT_EQ(plaintext, recovered_plaintext);

  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST(AsymmetricCryptTest, DecryptParametersMismatch) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  kms_v1::CryptoKeyVersion ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA512, CKG_MGF1_SHA512,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(DecryptInit(session, &mech, private_key),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST(AsymmetricCryptTest, DecryptInitFailsInvalidSessionHandle) {
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

TEST(AsymmetricCryptTest, DecryptInitFailsInvalidKeyHandle) {
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

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(DecryptInit(session, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST(AsymmetricCryptTest, DecryptInitFailsOperationActive) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  kms_v1::CryptoKeyVersion ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session, &mech, private_key));
  EXPECT_THAT(DecryptInit(session, &mech, private_key),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST(AsymmetricCryptTest, DecryptFailsOperationNotInitialized) {
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

TEST(AsymmetricCryptTest, DecryptFailsNullCiphertext) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  kms_v1::CryptoKeyVersion ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session, &mech, private_key));

  CK_ULONG plaintext_size;
  EXPECT_THAT(Decrypt(session, nullptr, 0, nullptr, &plaintext_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  uint8_t ciphertext[256];
  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST(AsymmetricCryptTest, DecryptFailsNullPlaintextSize) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  kms_v1::CryptoKeyVersion ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session, &mech, private_key));

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

TEST(AsymmetricCryptTest, EncryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  kms_v1::CryptoKeyVersion ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session, &mech, public_key));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  CK_ULONG ciphertext_size;
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                    &ciphertext_size));
  EXPECT_EQ(ciphertext_size, 256);

  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));

  // Operation should be terminated after success
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST(AsymmetricCryptTest, EncryptSuccessSameBuffer) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  kms_v1::CryptoKeyVersion ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));
  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session, &mech, public_key));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> buf(256);
  std::copy(plaintext.begin(), plaintext.end(), buf.data());

  CK_ULONG ciphertext_size = buf.size();
  EXPECT_OK(Encrypt(session, buf.data(), 128, buf.data(), &ciphertext_size));
  EXPECT_EQ(ciphertext_size, 256);

  EXPECT_OK(DecryptInit(session, &mech, private_key));

  std::vector<uint8_t> recovered_plaintext(128);
  CK_ULONG recovered_plaintext_size = recovered_plaintext.size();
  EXPECT_OK(Decrypt(session, buf.data(), buf.size(), recovered_plaintext.data(),
                    &recovered_plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);
}

TEST(AsymmetricCryptTest, EncryptBufferTooSmall) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  kms_v1::CryptoKeyVersion ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session, &mech, public_key));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> ciphertext(255);
  CK_ULONG ciphertext_size = ciphertext.size();
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(),
                      ciphertext.data(), &ciphertext_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(ciphertext_size, 256);

  // Operation should be able to proceed after CKR_BUFFER_TOO_SMALL.
  ciphertext.resize(ciphertext_size);
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));

  // Operation should now be terminated.
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST(AsymmetricCryptTest, EncryptParametersMismatch) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  kms_v1::CryptoKeyVersion ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA512, CKG_MGF1_SHA512,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(EncryptInit(session, &mech, public_key),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST(AsymmetricCryptTest, EncryptInitFailsInvalidSessionHandle) {
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

TEST(AsymmetricCryptTest, EncryptInitFailsInvalidKeyHandle) {
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

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(EncryptInit(session, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST(AsymmetricCryptTest, EncryptInitFailsOperationActive) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  kms_v1::CryptoKeyVersion ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session, &mech, public_key));
  EXPECT_THAT(EncryptInit(session, &mech, public_key),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST(AsymmetricCryptTest, EncryptFailsOperationNotInitialized) {
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

TEST(AsymmetricCryptTest, EncryptFailsNullPLaintext) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  kms_v1::CryptoKeyVersion ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session, &mech, public_key));

  CK_ULONG ciphertext_size;
  EXPECT_THAT(Encrypt(session, nullptr, 0, nullptr, &ciphertext_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  uint8_t plaintext[32];
  // Operation should now be terminated.
  EXPECT_THAT(
      Encrypt(session, plaintext, sizeof(plaintext), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST(AsymmetricCryptTest, EncryptFailsNullCiphertextSize) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  kms_v1::CryptoKeyVersion ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session, &mech, public_key));

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
