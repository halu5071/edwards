#include <iostream>
#include "point.hpp"

int hello() {
  return 1;
}

JNIEXPORT jint JNICALL Java_io_moatwel_crypto_eddsa_ed25519_PointEd25519_hello(JNIEnv *env, jobject object) {
  return;
}