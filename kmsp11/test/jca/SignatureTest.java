package kmsp11.test.jca;

import com.google.cloud.kms.v1.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Signature;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SignatureTest {

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
  public void testEcP256SignVerify() throws Exception {
    String cryptoKeyId = "ec-p256-key";
    createCkv(cryptoKeyId, CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256);

    signAndVerify(cryptoKeyId, "SHA256withECDSA");
  }

  @Test
  public void testEcP384SignVerify() throws Exception {
    String cryptoKeyId = "ec-p384-key";
    createCkv(cryptoKeyId, CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384);

    signAndVerify(cryptoKeyId, "SHA384withECDSA");
  }

  private void signAndVerify(String keyLabel, String jcaAlgorithm) throws Exception {
    Provider provider = f.newProvider();

    KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
    keyStore.load(null, null);
    KeyStore.Entry e = keyStore.getEntry(keyLabel, null);
    Assert.assertTrue(e instanceof KeyStore.PrivateKeyEntry);
    KeyStore.PrivateKeyEntry pk = (KeyStore.PrivateKeyEntry) e;

    byte[] data = "Here is some different data to authenticate".getBytes(StandardCharsets.UTF_8);

    Signature signer = Signature.getInstance(jcaAlgorithm, provider);
    signer.initSign(pk.getPrivateKey());
    signer.update(data);
    byte[] signature = signer.sign();

    // Verify using the retrieved certificate's public key + the Java standard
    // library.
    Signature verifier = Signature.getInstance(jcaAlgorithm);
    verifier.initVerify(pk.getCertificate().getPublicKey());
    verifier.update(data);
    Assert.assertTrue(verifier.verify(signature));
  }

  private CryptoKeyVersion createCkv(
      String cryptoKeyId, CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm) throws Exception {
    CreateCryptoKeyRequest ckReq =
        CreateCryptoKeyRequest.newBuilder()
            .setParent(f.getKeyRing().getName())
            .setCryptoKeyId(cryptoKeyId)
            .setCryptoKey(
                CryptoKey.newBuilder()
                    .setPurpose(CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN)
                    .setVersionTemplate(
                        CryptoKeyVersionTemplate.newBuilder()
                            .setAlgorithm(algorithm)
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
