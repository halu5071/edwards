package io.moatwel.crypto;

public interface KeyGenerator {

    KeyPair generateKeyPair();

    PublicKey derivePublicKey(PrivateKey privateKey);
}
