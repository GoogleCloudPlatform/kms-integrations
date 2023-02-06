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

class AsymmetricCryptTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_server_, fakekms::Server::New());
    kms_v1::KeyRing kr;
    config_file_ = CreateConfigFileWithOneKeyring(fake_server_.get(), &kr);
    auto init_args = InitArgs(config_file_.c_str());

    kms_v1::CryptoKeyVersion ckv = InitializeCryptoKeyAndKeyVersion(
        fake_server_.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
        kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
    ASSERT_OK_AND_ASSIGN(pub_pkey_, GetEVPPublicKey(fake_server_.get(), ckv));

    EXPECT_OK(Initialize(&init_args));
    EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session_));

    ASSERT_OK_AND_ASSIGN(private_key_,
                         GetPrivateKeyObjectHandle(session_, ckv));
    ASSERT_OK_AND_ASSIGN(public_key_, GetPublicKeyObjectHandle(session_, ckv));
  }

  void TearDown() override {
    std::remove(config_file_.c_str());
    EXPECT_OK(Finalize(nullptr));
  }

  std::string config_file_;
  std::unique_ptr<fakekms::Server> fake_server_;
  CK_SESSION_HANDLE session_;
  CK_OBJECT_HANDLE private_key_;
  CK_OBJECT_HANDLE public_key_;
  bssl::UniquePtr<EVP_PKEY> pub_pkey_;
};

TEST_F(AsymmetricCryptTest, DecryptSuccess) {
  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  uint8_t ciphertext[256];
  EXPECT_OK(EncryptRsaOaep(pub_pkey_.get(), EVP_sha256(), plaintext,
                           absl::MakeSpan(ciphertext)));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session_, &mech, private_key_));

  CK_ULONG plaintext_size;
  EXPECT_OK(Decrypt(session_, ciphertext, sizeof(ciphertext), nullptr,
                    &plaintext_size));
  EXPECT_EQ(plaintext_size, plaintext.size());

  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(Decrypt(session_, ciphertext, sizeof(ciphertext),
                    recovered_plaintext.data(), &plaintext_size));
  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session_, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricCryptTest, DecryptSuccessSameBuffer) {
  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> buf(256);
  EXPECT_OK(EncryptRsaOaep(pub_pkey_.get(), EVP_sha256(), plaintext,
                           absl::MakeSpan(buf)));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session_, &mech, private_key_));

  CK_ULONG plaintext_size = buf.size();
  EXPECT_OK(
      Decrypt(session_, buf.data(), buf.size(), buf.data(), &plaintext_size));
  EXPECT_EQ(plaintext_size, plaintext.size());

  buf.resize(plaintext_size);
  EXPECT_EQ(buf, plaintext);
}

TEST_F(AsymmetricCryptTest, DecryptBufferTooSmall) {
  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  uint8_t ciphertext[256];
  EXPECT_OK(EncryptRsaOaep(pub_pkey_.get(), EVP_sha256(), plaintext,
                           absl::MakeSpan(ciphertext)));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session_, &mech, private_key_));

  std::vector<uint8_t> recovered_plaintext(32);
  CK_ULONG plaintext_size = recovered_plaintext.size();
  EXPECT_THAT(Decrypt(session_, ciphertext, sizeof(ciphertext),
                      recovered_plaintext.data(), &plaintext_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be able to proceed after CKR_BUFFER_TOO_SMALL.
  recovered_plaintext.resize(plaintext_size);
  EXPECT_OK(Decrypt(session_, ciphertext, sizeof(ciphertext),
                    recovered_plaintext.data(), &plaintext_size));
  EXPECT_EQ(plaintext, recovered_plaintext);

  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session_, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricCryptTest, DecryptParametersMismatch) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA512, CKG_MGF1_SHA512,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(DecryptInit(session_, &mech, private_key_),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST_F(AsymmetricCryptTest, DecryptInitFailsInvalidSessionHandle) {
  EXPECT_THAT(DecryptInit(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(AsymmetricCryptTest, DecryptInitFailsInvalidKeyHandle) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(DecryptInit(session_, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_F(AsymmetricCryptTest, DecryptInitFailsOperationActive) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session_, &mech, private_key_));
  EXPECT_THAT(DecryptInit(session_, &mech, private_key_),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(AsymmetricCryptTest, DecryptFailsOperationNotInitialized) {
  uint8_t ciphertext[256];
  CK_ULONG plaintext_size;
  EXPECT_THAT(Decrypt(session_, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricCryptTest, DecryptFailsNullCiphertext) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session_, &mech, private_key_));

  CK_ULONG plaintext_size;
  EXPECT_THAT(Decrypt(session_, nullptr, 0, nullptr, &plaintext_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  uint8_t ciphertext[256];
  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session_, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricCryptTest, DecryptFailsNullPlaintextSize) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session_, &mech, private_key_));

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

TEST_F(AsymmetricCryptTest, EncryptSuccess) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session_, &mech, public_key_));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  CK_ULONG ciphertext_size;
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                    &ciphertext_size));
  EXPECT_EQ(ciphertext_size, 256);

  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));

  // Operation should be terminated after success
  EXPECT_THAT(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricCryptTest, EncryptSuccessSameBuffer) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session_, &mech, public_key_));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> buf(256);
  std::copy(plaintext.begin(), plaintext.end(), buf.data());

  CK_ULONG ciphertext_size = buf.size();
  EXPECT_OK(Encrypt(session_, buf.data(), 128, buf.data(), &ciphertext_size));
  EXPECT_EQ(ciphertext_size, 256);

  EXPECT_OK(DecryptInit(session_, &mech, private_key_));

  std::vector<uint8_t> recovered_plaintext(128);
  CK_ULONG recovered_plaintext_size = recovered_plaintext.size();
  EXPECT_OK(Decrypt(session_, buf.data(), buf.size(),
                    recovered_plaintext.data(), &recovered_plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);
}

TEST_F(AsymmetricCryptTest, EncryptBufferTooSmall) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session_, &mech, public_key_));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> ciphertext(255);
  CK_ULONG ciphertext_size = ciphertext.size();
  EXPECT_THAT(Encrypt(session_, plaintext.data(), plaintext.size(),
                      ciphertext.data(), &ciphertext_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(ciphertext_size, 256);

  // Operation should be able to proceed after CKR_BUFFER_TOO_SMALL.
  ciphertext.resize(ciphertext_size);
  EXPECT_OK(Encrypt(session_, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));

  // Operation should now be terminated.
  EXPECT_THAT(Encrypt(session_, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricCryptTest, EncryptParametersMismatch) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA512, CKG_MGF1_SHA512,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(EncryptInit(session_, &mech, public_key_),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST_F(AsymmetricCryptTest, EncryptInitFailsInvalidSessionHandle) {
  EXPECT_THAT(EncryptInit(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_F(AsymmetricCryptTest, EncryptInitFailsInvalidKeyHandle) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(EncryptInit(session_, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_F(AsymmetricCryptTest, EncryptInitFailsOperationActive) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session_, &mech, public_key_));
  EXPECT_THAT(EncryptInit(session_, &mech, public_key_),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(AsymmetricCryptTest, EncryptFailsOperationNotInitialized) {
  uint8_t plaintext[32];
  CK_ULONG ciphertext_size;
  EXPECT_THAT(Encrypt(session_, plaintext, sizeof(plaintext), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricCryptTest, EncryptFailsNullPLaintext) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session_, &mech, public_key_));

  CK_ULONG ciphertext_size;
  EXPECT_THAT(Encrypt(session_, nullptr, 0, nullptr, &ciphertext_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  uint8_t plaintext[32];
  // Operation should now be terminated.
  EXPECT_THAT(Encrypt(session_, plaintext, sizeof(plaintext), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(AsymmetricCryptTest, EncryptFailsNullCiphertextSize) {
  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session_, &mech, public_key_));

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
