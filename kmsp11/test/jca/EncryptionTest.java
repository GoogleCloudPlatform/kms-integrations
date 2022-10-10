// Copyright 2022 Google LLC
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

package kmsp11.test.jca;

import com.google.cloud.kms.v1.*;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Provider;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class EncryptionTest {
  private JcaTestFixture f;

  @Before
  public void setup() throws IOException {
    f = new JcaTestFixture();
  }

  @After
  public void tearDown() {
    f.close();
  }

  @Test
  public void testAes128CtrEncryptDecrypt() throws Exception {
    String cryptoKeyId = "aes-128-ctr-key";
    // TODO(b/234842124): use real enum values once the KMS proto changes are public.
    CryptoKeyVersion ckv = createCkv(cryptoKeyId, /* RAW_ENCRYPT_DECRYPT */ 7,
        /* AES_128_CTR */ 44);

    aesCtrEncryptMatchesExpected(cryptoKeyId, ckv.getName(), "AES/CTR/NoPadding");
    aesCtrEncryptDecrypt(cryptoKeyId, "AES/CTR/NoPadding");
  }

  @Test
  public void testAes256CtrEncryptDecrypt() throws Exception {
    String cryptoKeyId = "aes-256-ctr-key";
    // TODO(b/234842124): use real enum values once the KMS proto changes are public.
    CryptoKeyVersion ckv = createCkv(cryptoKeyId, /* RAW_ENCRYPT_DECRYPT */ 7,
        /* AES_256_CTR */ 45);

    aesCtrEncryptMatchesExpected(cryptoKeyId, ckv.getName(), "AES/CTR/NoPadding");
    aesCtrEncryptDecrypt(cryptoKeyId, "AES/CTR/NoPadding");
  }

  private void aesCtrEncryptDecrypt(String keyLabel, String jcaAlgorithm) throws Exception {
    byte[] data = "Here is some data to encrypt".getBytes(StandardCharsets.UTF_8);
    byte[] iv = "my_custom_iv_123".getBytes(StandardCharsets.UTF_8);
    IvParameterSpec spec = new IvParameterSpec(iv);

    Provider provider = f.newProvider();
    KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
    keyStore.load(null, null);
    KeyStore.Entry e = keyStore.getEntry(keyLabel, null);
    Assert.assertTrue(e instanceof KeyStore.SecretKeyEntry);

    KeyStore.SecretKeyEntry sk = (KeyStore.SecretKeyEntry) e;
    Assert.assertTrue(sk.getSecretKey() != null);
    Assert.assertTrue(sk.getSecretKey().getFormat() == null);
    Assert.assertTrue(sk.getSecretKey().getEncoded() == null);
    Assert.assertTrue(sk.getSecretKey().getAlgorithm() == "AES");

    Cipher cipher = Cipher.getInstance(jcaAlgorithm, provider);
    cipher.init(Cipher.ENCRYPT_MODE, sk.getSecretKey(), spec);
    byte[] ciphertext = new byte[cipher.getOutputSize(data.length)];
    cipher.update(data);
    cipher.doFinal(ciphertext, 0);

    cipher.init(Cipher.DECRYPT_MODE, sk.getSecretKey(), spec);
    byte[] recovered_plaintext = new byte[cipher.getOutputSize(ciphertext.length)];
    cipher.update(ciphertext);

    cipher.doFinal(recovered_plaintext, 0);

    Assert.assertTrue(Arrays.equals(recovered_plaintext, data));
  }

  private void aesCtrEncryptMatchesExpected(
      String keyLabel, String versionName, String jcaAlgorithm) throws Exception {
    byte[] data = "Here is some data to encrypt".getBytes(StandardCharsets.UTF_8);
    byte[] iv = "my_custom_iv_123".getBytes(StandardCharsets.UTF_8);

    // Encrypt using KMS directly (RawEncrypt).
    RawEncryptRequest encryptReq = RawEncryptRequest.newBuilder()
                                       .setName(versionName)
                                       .setPlaintext(ByteString.copyFrom(data))
                                       .setInitializationVector(ByteString.copyFrom(iv))
                                       .build();

    RawEncryptResponse encryptResp = f.getClient().rawEncrypt(encryptReq);
    byte[] responseIv = encryptResp.getInitializationVector().toByteArray();
    Assert.assertTrue(Arrays.equals(responseIv, iv));
    byte[] expected_ciphertext = encryptResp.getCiphertext().toByteArray();

    Provider provider = f.newProvider();
    KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
    keyStore.load(null, null);
    KeyStore.Entry e = keyStore.getEntry(keyLabel, null);
    Assert.assertTrue(e instanceof KeyStore.SecretKeyEntry);

    KeyStore.SecretKeyEntry sk = (KeyStore.SecretKeyEntry) e;
    Assert.assertTrue(sk.getSecretKey() != null);
    Assert.assertTrue(sk.getSecretKey().getFormat() == null);
    Assert.assertTrue(sk.getSecretKey().getEncoded() == null);
    Assert.assertTrue(sk.getSecretKey().getAlgorithm() == "AES");

    Cipher cipher = Cipher.getInstance(jcaAlgorithm, provider);
    IvParameterSpec spec = new IvParameterSpec(responseIv);
    cipher.init(Cipher.ENCRYPT_MODE, sk.getSecretKey(), spec);
    byte[] ciphertext = new byte[cipher.getOutputSize(data.length)];
    cipher.update(data);
    cipher.doFinal(ciphertext, 0);

    Assert.assertTrue(Arrays.equals(ciphertext, expected_ciphertext));
  }

  private CryptoKeyVersion createCkv(String cryptoKeyId, CryptoKey.CryptoKeyPurpose purpose,
      CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm) throws Exception {
    return createCkv(cryptoKeyId, purpose.getNumber(), algorithm.getNumber());
  }

  // TODO(b/234842124): drop overload once the KMS proto changes are public.
  private CryptoKeyVersion createCkv(String cryptoKeyId, int purposeID, int algorithmID)
      throws Exception {
    CreateCryptoKeyRequest ckReq =
        CreateCryptoKeyRequest.newBuilder()
            .setParent(f.getKeyRing().getName())
            .setCryptoKeyId(cryptoKeyId)
            .setCryptoKey(CryptoKey.newBuilder().setPurposeValue(purposeID).setVersionTemplate(
                CryptoKeyVersionTemplate.newBuilder()
                    .setAlgorithmValue(algorithmID)
                    .setProtectionLevel(ProtectionLevel.HSM)))
            .setSkipInitialVersionCreation(true)
            .build();

    CryptoKey ck = f.getClient().createCryptoKey(ckReq);
    CryptoKeyVersion ckv =
        f.getClient().createCryptoKeyVersion(ck.getName(), CryptoKeyVersion.getDefaultInstance());

    while (ckv.getState() != CryptoKeyVersion.CryptoKeyVersionState.ENABLED) {
      Thread.sleep(1 /* millisecond */);
      ckv = f.getClient().getCryptoKeyVersion(ckv.getName());
    }

    return ckv;
  }
}
