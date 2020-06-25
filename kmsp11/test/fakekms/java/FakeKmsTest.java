package com.google.cloud.kms.pkcs11.fakekms;

import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyRing;
import org.junit.Assert;
import org.junit.Test;

public class FakeKmsTest {

  @Test
  public void smokeTest() throws Exception {
    try (FakeKms fake = new FakeKms()) {
      try (KeyManagementServiceClient client = fake.newClient()) {
        KeyRing kr =
            client.createKeyRing(
                "projects/foo/locations/global", "my-key-ring", KeyRing.getDefaultInstance());
        Assert.assertEquals(kr.getName(), "projects/foo/locations/global/keyRings/my-key-ring");
      }
    }
  }
}
