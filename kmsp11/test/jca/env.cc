#include <jni.h>

#include "kmsp11/util/platform.h"

extern "C" {

JNIEXPORT void JNICALL Java_kmsp11_test_jca_Environment_setenv(JNIEnv* env,
                                                               jclass cl,
                                                               jstring name,
                                                               jstring value) {
  const char* name_chars = env->GetStringUTFChars(name, nullptr);
  const char* value_chars = env->GetStringUTFChars(value, nullptr);
  kmsp11::SetEnvVariable(name_chars, value_chars);
  env->ReleaseStringUTFChars(name, name_chars);
  env->ReleaseStringUTFChars(value, value_chars);
}

JNIEXPORT void JNICALL Java_kmsp11_test_jca_Environment_unsetenv(JNIEnv* env,
                                                                 jclass cl,
                                                                 jstring name) {
  const char* name_chars = env->GetStringUTFChars(name, nullptr);
  kmsp11::ClearEnvVariable(name_chars);
  env->ReleaseStringUTFChars(name, name_chars);
}
}
