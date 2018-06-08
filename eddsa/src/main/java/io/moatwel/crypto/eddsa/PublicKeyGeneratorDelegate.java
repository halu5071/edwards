package io.moatwel.crypto.eddsa;

import io.moatwel.crypto.PrivateKey;

public interface PublicKeyGeneratorDelegate {

    byte[] generatePublicKeyByteArray(PrivateKey privateKey);
}
