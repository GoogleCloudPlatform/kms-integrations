package com.google.cloud.kms.pkcs11.fakekms;

import com.google.api.gax.core.NoCredentialsProvider;
import com.google.api.gax.grpc.GrpcTransportChannel;
import com.google.api.gax.rpc.FixedTransportChannelProvider;
import com.google.api.gax.rpc.TransportChannelProvider;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.devtools.build.runfiles.Runfiles;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/** FakeKms provides a Java language binding to a fake Cloud KMS server. */
public class FakeKms implements AutoCloseable {

  private static final String FAKEKMS_PATH =
      "com_google_kmstools/kmsp11/test/fakekms/main/fakekms_/"
          + (System.getProperty("os.name").startsWith("Windows") ? "fakekms.exe" : "fakekms");

  private final Process process;
  private final String serverAddress;

  /** Creates and starts a new Fake KMS server. */
  public FakeKms() throws IOException {
    String serverPath = Runfiles.create().rlocation(FAKEKMS_PATH);
    process = Runtime.getRuntime().exec(serverPath);
    serverAddress = new BufferedReader(new InputStreamReader(process.getInputStream())).readLine();
  }

  /** Returns a new KMS client that is wired to this fake. */
  public KeyManagementServiceClient newClient() throws IOException {
    ManagedChannel channel = ManagedChannelBuilder.forTarget(serverAddress).usePlaintext().build();
    TransportChannelProvider channelProvider =
        FixedTransportChannelProvider.create(GrpcTransportChannel.create(channel));

    KeyManagementServiceSettings clientSettings =
        KeyManagementServiceSettings.newBuilder()
            .setTransportChannelProvider(channelProvider)
            .setCredentialsProvider(new NoCredentialsProvider())
            .build();

    return KeyManagementServiceClient.create(clientSettings);
  }

  public String getServerAddress() {
    return serverAddress;
  }

  /** Stops the fake server and releases all resources associated with it. */
  @Override
  public void close() {
    if (process.isAlive()) {
      process.destroy();
    }
  }
}
