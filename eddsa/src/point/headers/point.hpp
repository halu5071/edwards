#ifndef POINT_H
#define POINT_H

#include <jni.h>

int hello();

JNIEXPORT jint JNICALL Java_io_moatwel_crypto_eddsa_ed25519_PointEd25519_hello(JNIEnv *env, jobject object);

#endif