package kmsp11.test.jca;

import com.google.common.base.Strings;
import com.google.devtools.build.runfiles.Runfiles;
import java.io.IOException;

/**
 * Class environment exposes static methods to set environment variables. Java does not provide
 * standard library support for setting environment variables, so we are forced to use JNI.
 *
 * <p>In a typical JCA deployment, the environment variable containing libkmsp11 config would be set
 * as part of the server configuration. However, since these integration tests point at a fake that
 * isn't instantiated until runtime, we must set our configuration at runtime as well.
 */
public class Environment {
  private static final String LIBENV_LOCATION = "com_google_kmstools/kmsp11/test/jca/libenv.so";

  static {
    try {
      Runtime.getRuntime().load(Runfiles.create().rlocation(LIBENV_LOCATION));
    } catch (IOException e) {
      throw new RuntimeException("failure loading libenv.so", e);
    }
  }

  private Environment() {} // no instances

  /** Set the environment variable with the provided name to the provided value. */
  public static void set(String name, String value) {
    if (Strings.isNullOrEmpty(name)) {
      throw new IllegalArgumentException("name must be set");
    }
    if (Strings.isNullOrEmpty(value)) {
      throw new IllegalArgumentException("value must be set");
    }
    setenv(name, value);
  }

  /** Unset the environment variable with the provided name. */
  public static void unset(String name) {
    if (Strings.isNullOrEmpty(name)) {
      throw new IllegalArgumentException("name must be set");
    }
    unsetenv(name);
  }

  private static native void setenv(String name, String value);

  private static native void unsetenv(String name);
}
